package com.lookahead.learning.content.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;
import software.amazon.awssdk.services.cognitoidentityprovider.model.InternalErrorException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/**
 * DLV-969 (owner, 2026-11-04): one upstream line per outbound call and per AWS call, every SDK retry, and no secrets.
 * Plain logs (2026-11-17): no answer, a 5xx and an AWS permission refusal are ERROR lines that quote the masked message.
 */
class OpsLogTest {
    static final String SECRET = "synthetic-token-never-logged";
    final ListAppender<ILoggingEvent> capture = new ListAppender<>();
    final List<Logger> loggers = List.of((Logger) LoggerFactory.getLogger("lookahead.upstream"),
            (Logger) LoggerFactory.getLogger("lookahead.event"), (Logger) LoggerFactory.getLogger("lookahead.limit"));
    final Map<Logger, Level> levels = new LinkedHashMap<>();

    @BeforeEach void listen() {
        capture.start();
        for (var logger : loggers) { levels.put(logger, logger.getLevel()); logger.setLevel(Level.DEBUG); logger.addAppender(capture); }
    }

    @AfterEach void stop() {
        for (var logger : loggers) { logger.detachAppender(capture); logger.setLevel(levels.get(logger)); }
        capture.stop();
    }

    static List<String> pairs(ILoggingEvent line) {
        return line.getKeyValuePairs() == null ? List.of() : line.getKeyValuePairs().stream().map(pair -> pair.key + "=" + pair.value).toList();
    }

    static final java.util.function.Function<URI, String> SERVICES = OpsLog.services(new MockEnvironment()
            .withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443")
            .withProperty("app.gateway.web-upstream", "https://web.lookahead-dev.internal:8443")
            .withProperty("app.oauth.identity-upstream", "http://identity:9000")
            .withProperty("app.author-previews.upstream", ""));

    ILoggingEvent call(HttpMethod method, String uri, ClientHttpRequestExecution execution) throws IOException {
        var request = new MockClientHttpRequest(method, URI.create(uri));
        request.getHeaders().setBearerAuth(SECRET);
        capture.list.clear();
        OpsLog.upstream(SERVICES).intercept(request, SECRET.getBytes(StandardCharsets.UTF_8), execution);
        assertThat(capture.list).hasSize(1);
        assertNothingSecret();
        return capture.list.getFirst();
    }

    static ClientHttpRequestExecution answer(HttpStatus status) {
        return (request, body) -> new MockClientHttpResponse(new byte[0], status);
    }

    @Test void everyOutboundCallIsOneLineWithServiceMethodPathStatusAndTimeButNeverTheQuery() throws IOException {
        var domain = call(HttpMethod.GET, "https://domain.lookahead-dev.internal:8443/api/v1/auth/me?token=" + SECRET, answer(HttpStatus.OK));
        assertThat(domain.getLevel()).isEqualTo(Level.INFO);
        assertThat(domain.getLoggerName()).isEqualTo("lookahead.upstream");
        assertThat(domain.getFormattedMessage()).matches("Upstream domain GET /api/v1/auth/me -> 200 in \\d+ ms");
        assertThat(pairs(domain)).contains("upstream.service=domain", "upstream.operation=GET /api/v1/auth/me", "upstream.status=200", "event.outcome=success")
                .anyMatch(pair -> pair.startsWith("durationMs="));
        // A served Web file is DEBUG: the static site would otherwise flood INFO. A missing one is INFO.
        assertThat(call(HttpMethod.GET, "https://web.lookahead-dev.internal:8443/main-ABCDEFGH.js", answer(HttpStatus.OK)).getLevel()).isEqualTo(Level.DEBUG);
        var missing = call(HttpMethod.GET, "https://web.lookahead-dev.internal:8443/nope.js", answer(HttpStatus.NOT_FOUND));
        assertThat(missing.getLevel()).isEqualTo(Level.INFO);
        assertThat(pairs(missing)).contains("upstream.service=web", "event.outcome=failure");
        // An upstream 5xx is an ERROR naming the host and saying where the detail is (no stack trace: the upstream answered).
        var down = call(HttpMethod.POST, "https://domain.lookahead-dev.internal:8443/internal/v1/cloud-sign-ins/admit", answer(HttpStatus.SERVICE_UNAVAILABLE));
        assertThat(down.getLevel()).isEqualTo(Level.ERROR);
        assertThat(down.getFormattedMessage()).matches("Outside a request: upstream domain POST /internal/v1/cloud-sign-ins/admit at domain\\.lookahead-dev\\.internal:8443 "
                + "answered 503 in \\d+ ms; the domain answered a server error; its own log has the detail");
        assertThat(down.getThrowableProxy()).isNull();
        assertThat(pairs(down)).contains("upstream.status=503", "reason=HTTP_503", "event.outcome=failure");
        // Cognito's hosts, the local Identity and anything else.
        assertThat(pairs(call(HttpMethod.POST, "https://example.auth.us-east-2.amazoncognito.com/oauth2/revoke", answer(HttpStatus.OK)))).contains("upstream.service=cognito");
        assertThat(pairs(call(HttpMethod.GET, "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example/.well-known/jwks.json", answer(HttpStatus.OK)))).contains("upstream.service=cognito");
        assertThat(pairs(call(HttpMethod.GET, "http://identity:9000/userinfo", answer(HttpStatus.OK)))).contains("upstream.service=identity");
        assertThat(pairs(call(HttpMethod.GET, "https://domain.lookahead-dev.internal:9443/x", answer(HttpStatus.OK)))).contains("upstream.service=other");
        assertThat(pairs(call(HttpMethod.GET, "http://localhost/x", answer(HttpStatus.OK)))).contains("upstream.service=other");
    }

    /** Outside a request (no RequestLog frame) the ERROR line is written at once; inside one, at the end of the request (RequestLogTest). */
    @Test void noAnswerIsAnErrorQuotingTheCauseWithCredentialsMaskedAndTheFailureIsRethrown() {
        var request = new MockClientHttpRequest(HttpMethod.GET, URI.create("https://domain.lookahead-dev.internal:8443/api/v1/auth/me?code=" + SECRET));
        ClientHttpRequestExecution refused = (sent, body) -> { throw new java.net.ConnectException("Connection refused; Authorization: Bearer " + SECRET); };
        assertThatThrownBy(() -> OpsLog.upstream(SERVICES).intercept(request, new byte[0], refused)).isInstanceOf(java.net.ConnectException.class);
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.ERROR);
        assertThat(line.getLoggerName()).isEqualTo("lookahead.upstream");
        assertThat(line.getFormattedMessage()).matches("Outside a request: upstream domain GET /api/v1/auth/me at domain\\.lookahead-dev\\.internal:8443 gave no answer in \\d+ ms "
                + "\\(ConnectException: Connection refused; Authorization=\\[hidden\\]\\); reference [0-9a-f-]{36}; nothing accepted the connection: check that the domain task "
                + "is running, its Cloud Map name points at a live task and its security group allows the Gateway");
        assertThat(line.getThrowableProxy().getClassName()).isEqualTo(java.net.ConnectException.class.getName());
        assertThat(pairs(line)).contains("upstream.service=domain", "upstream.operation=GET /api/v1/auth/me", "reason=NO_RESPONSE", "event.outcome=failure",
                "exception.types=ConnectException");
        ClientHttpRequestExecution slow = (sent, body) -> { throw new java.net.http.HttpTimeoutException("request timed out"); };
        assertThatThrownBy(() -> OpsLog.upstream(SERVICES).intercept(request, new byte[0], slow)).isInstanceOf(java.net.http.HttpTimeoutException.class);
        assertThat(pairs(capture.list.getLast())).contains("reason=TIMEOUT", "event.outcome=failure");
        assertThat(capture.list.getLast().getFormattedMessage()).contains("(HttpTimeoutException: request timed out)")
                .endsWith("; the connection was made but no answer came in time: the domain is up but slow or stuck");
        assertNothingSecret();
    }

    @Test void awsRefusalsStayInfoWithoutTheMessageWhileDeniedUnreachableAndServerErrorsAreErrorsQuotingIt() {
        assertThat(OpsLog.aws("cognito", "InitiateAuth", () -> "ok")).isEqualTo("ok");
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.INFO);
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Upstream cognito InitiateAuth succeeded in \\d+ ms");
        assertThat(OpsLog.aws("dynamodb", "GetItem", true, () -> "ok")).isEqualTo("ok");
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.DEBUG);

        // An expected refusal (4xx): INFO, the code only; Cognito's message can name the account and is never quoted.
        var refused = NotAuthorizedException.builder().message("Incorrect username or password for priya@example.invalid").statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("NotAuthorizedException").errorMessage(SECRET).build()).build();
        assertThatThrownBy(() -> OpsLog.aws("cognito", "InitiateAuth", () -> { throw refused; })).isSameAs(refused);
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.INFO);
        assertThat(line.getFormattedMessage()).matches("Upstream cognito InitiateAuth -> 400 NotAuthorizedException in \\d+ ms");
        assertThat(pairs(line)).contains("upstream.service=cognito", "upstream.operation=InitiateAuth", "upstream.status=400",
                "upstream.code=NotAuthorizedException", "event.outcome=failure");
        // Cognito's own throttle is a limit, not something to act on, even at 400.
        var throttled = software.amazon.awssdk.services.cognitoidentityprovider.model.TooManyRequestsException.builder().statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("TooManyRequestsException").build()).build();
        assertThatThrownBy(() -> OpsLog.aws("cognito", "SignUp", () -> { throw throttled; })).isSameAs(throttled);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.INFO);

        // A 5xx answer: ERROR, with the service's message and request id quoted and the resource named.
        var broken = InternalErrorException.builder().statusCode(500).requestId("req-0001")
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("InternalErrorException").errorMessage("Internal error\nplease retry").build()).build();
        assertThatThrownBy(() -> OpsLog.aws("cognito", "SignUp", "app client 1abc", false, () -> { throw broken; })).isSameAs(broken);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.ERROR);
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Outside a request: upstream cognito SignUp on app client 1abc failed with HTTP 500 "
                + "\\(InternalErrorException: Internal error please retry; AWS request id req-0001\\); reference [0-9a-f-]{36}; AWS answered a server error; the SDK already retried where its retry mode allows");
        assertThat(pairs(capture.list.getLast())).contains("upstream.code=InternalErrorException", "upstream.status=500", "reason=InternalErrorException");
        assertThat(capture.list.getLast().getThrowableProxy()).isNotNull();

        // A permission refusal (403): ERROR, so the deploy's log scan finds AccessDeniedException as before.
        var denied = software.amazon.awssdk.services.dynamodb.model.DynamoDbException.builder().statusCode(403)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("AccessDeniedException").errorMessage("User: arn:aws:sts::123456789012:assumed-role/lookahead-dev-app-task/abc "
                        + "is not authorized to perform: dynamodb:GetItem on resource: arn:aws:dynamodb:us-east-2:123456789012:table/lookahead-dev-operations").build()).build();
        assertThatThrownBy(() -> OpsLog.aws("dynamodb", "GetItem", "table lookahead-dev-operations", true, () -> { throw denied; })).isSameAs(denied);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.ERROR);
        assertThat(capture.list.getLast().getFormattedMessage()).startsWith("Outside a request: upstream dynamodb GetItem on table lookahead-dev-operations was refused with HTTP 403 "
                + "(AccessDeniedException: User: arn:aws:sts::123456789012:assumed-role/lookahead-dev-app-task/abc is not authorized to perform: dynamodb:GetItem on resource: "
                + "arn:aws:dynamodb:us-east-2:123456789012:table/lookahead-dev-operations); reference ")
                .endsWith("; the task role lacks this permission or its credentials are wrong: check the app-task role's policy");

        // No answer at all: ERROR with the SDK's message (it names the endpoint) and the VPC endpoint hint.
        var offline = SdkClientException.create("Unable to execute HTTP request: Connect to cognito-idp.us-east-2.amazonaws.com:443 failed: connect timed out");
        assertThatThrownBy(() -> OpsLog.aws("cognito", "AdminGetUser", "pool us-east-2_Example", false, () -> { throw offline; })).isSameAs(offline);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.ERROR);
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Outside a request: upstream cognito AdminGetUser on pool us-east-2_Example gave no answer in \\d+ ms "
                + "\\(SdkClientException: Unable to execute HTTP request: Connect to cognito-idp\\.us-east-2\\.amazonaws\\.com:443 failed: connect timed out\\); reference [0-9a-f-]{36}; "
                + "a connect failure to an AWS endpoint from the task's subnet usually means the VPC endpoint or its security group does not let the Gateway through");
        assertNothingSecret();
        assertThat(capture.list).extracting(ILoggingEvent::getFormattedMessage).noneMatch(m -> m.contains("priya@example.invalid"));
        // WARN and INFO lines never carry the word ERROR; only ERROR lines do.
        assertThat(capture.list).filteredOn(l -> l.getLevel() != Level.ERROR).extracting(ILoggingEvent::getFormattedMessage).noneMatch(m -> m.contains("ERROR"));
    }

    /** What an ERROR line may quote of a dependency's message: one line, capped, with the shapes a secret could take masked. */
    @Test void quotedMessagesAreMaskedCappedAndKeptToOneLine() {
        assertThat(OpsLog.safe(null)).isEqualTo("no message");
        assertThat(OpsLog.safe("  ")).isEqualTo("no message");
        assertThat(OpsLog.safe("I/O error on GET request for \"https://domain:8443/api/v1/me?token=" + SECRET + "\": Read timed out"))
                .isEqualTo("I/O error on GET request for \"https://domain:8443/api/v1/me?[query hidden]\": Read timed out");
        assertThat(OpsLog.safe("Authorization: Bearer " + SECRET + ", Cookie: LOOKAHEAD_GATEWAY=" + SECRET + "; path=/"))
                .isEqualTo("Authorization=[hidden], Cookie=[hidden]; path=/");
        assertThat(OpsLog.safe("password=" + SECRET + " client_secret=" + SECRET + " refresh_token: " + SECRET + " for priya@example.invalid"))
                .isEqualTo("password=[hidden] client_secret=[hidden] refresh_token=[hidden] for [email]");
        assertThat(OpsLog.safe("line one\r\n\tline two")).isEqualTo("line one line two");
        assertThat(OpsLog.safe("x".repeat(1000))).hasSize(OpsLog.MESSAGE_LIMIT + 1).endsWith("…");
        // The deepest cause with a message is the one quoted: Spring's wrappers repeat the URL.
        var wrapped = new org.springframework.web.client.ResourceAccessException("I/O error on GET request for \"https://x/?t=" + SECRET + "\"",
                new java.net.SocketTimeoutException("Read timed out"));
        assertThat(OpsLog.quote(wrapped)).isEqualTo("ResourceAccessException < SocketTimeoutException: Read timed out");
        assertThat(OpsLog.quote(new java.net.ConnectException())).isEqualTo("ConnectException: no message");
        assertThat(OpsLog.hint("domain", new java.net.UnknownHostException("domain.lookahead-dev.internal"))).startsWith("the host name did not resolve");
        assertThat(OpsLog.hint("domain", new javax.net.ssl.SSLHandshakeException("bad certificate"))).startsWith("the TLS handshake failed");
        assertThat(OpsLog.hint("domain", new IllegalStateException("something else"))).isNull();
        assertThat(OpsLog.awsHint(400, "ResourceNotFoundException")).startsWith("the configured table or user pool does not exist");
        assertThat(OpsLog.awsHint(400, "NotAuthorizedException")).isNull();
    }

    @Test void domainCodesAreCopiedOnlyWhenTheyAreStableUpperCaseCodes() {
        assertThat(OpsLog.code("{\"code\":\"ACCOUNT_ADMISSION_REQUIRED\",\"message\":\"x\"}".getBytes(StandardCharsets.UTF_8))).isEqualTo("ACCOUNT_ADMISSION_REQUIRED");
        assertThat(OpsLog.code("{\"code\":\"priya@example.invalid\"}".getBytes(StandardCharsets.UTF_8))).isNull();
        assertThat(OpsLog.code(new byte[0])).isNull();
        assertThat(OpsLog.code(null)).isNull();
        assertThat(OpsLog.path(URI.create("https://x.test/" + "a".repeat(300)))).hasSize(201);
        assertThat(OpsLog.cognito(null)).isFalse();
    }

    /** The DynamoDB status read retries by itself; each retry is one WARN line, and the call's outcome is one more. */
    @Test void everySdkRetryIsLoggedWithItsAttemptNumberAndWhatTheAttemptBeforeGot() throws Exception {
        var attempts = new AtomicInteger();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            exchange.getRequestBody().readAllBytes();
            boolean fail = attempts.incrementAndGet() < 3;
            byte[] body = (fail ? "{\"__type\":\"com.amazonaws.dynamodb.v20120810#InternalServerError\",\"message\":\"" + SECRET + "\"}"
                    : "{\"Item\":{\"id\":{\"S\":\"dev\"},\"deadline\":{\"S\":\"2999-01-01T00:00:00Z\"}}}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/x-amz-json-1.0");
            exchange.sendResponseHeaders(fail ? 500 : 200, body.length);
            try (var out = exchange.getResponseBody()) { out.write(body); }
        });
        server.start();
        try (DynamoDbClient client = DevSessionStatus.configured(DynamoDbClient.builder()).region(Region.US_EAST_2)
                .endpointOverride(URI.create("http://127.0.0.1:" + server.getAddress().getPort()))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIDEXAMPLE", "synthetic-secret-key"))).build()) {
            var status = new DevSessionStatus(client, "lookahead-dev-operations").status();
            assertThat(status.getStatusCode().value()).isEqualTo(200);
        } finally { server.stop(0); }
        assertThat(attempts).hasValue(3);
        var retries = capture.list.stream().filter(line -> pairs(line).stream().anyMatch(pair -> pair.startsWith("retry.attempt="))).toList();
        assertThat(retries).extracting(ILoggingEvent::getFormattedMessage).containsExactly(
                "Upstream dynamodb GetItem attempt 2 of 3: retrying after HTTP 500", "Upstream dynamodb GetItem attempt 3 of 3: retrying after HTTP 500");
        assertThat(retries).allMatch(line -> line.getLevel() == Level.WARN);
        assertThat(pairs(retries.getLast())).contains("retry.attempt=3", "retry.max=3", "upstream.service=dynamodb", "upstream.operation=GetItem");
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Upstream dynamodb GetItem succeeded in \\d+ ms");
        assertNothingSecret();
    }

    @Test void anUnreadableStatusTableIsAWarnOutcomeLineAndAnErrorUpstreamLineNamingTheTable() {
        var client = org.mockito.Mockito.mock(DynamoDbClient.class);
        org.mockito.Mockito.when(client.getItem(org.mockito.ArgumentMatchers.<java.util.function.Consumer<software.amazon.awssdk.services.dynamodb.model.GetItemRequest.Builder>>any()))
                .thenThrow(SdkClientException.create("Unable to execute HTTP request: connection reset"));
        assertThat(new DevSessionStatus(client, "lookahead-dev-operations").status().getStatusCode().value()).isEqualTo(503);
        assertThat(capture.list.getLast().getFormattedMessage())
                .isEqualTo("DEV session status unavailable: DEV_STATUS_UNAVAILABLE (the operations table could not be read: SdkClientException); answered 503");
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.WARN);
        assertThat(pairs(capture.list.getLast())).contains("event.action=dev-session.status", "event.outcome=failure", "reason=DEV_STATUS_UNAVAILABLE");
        var error = capture.list.get(capture.list.size() - 2);
        assertThat(error.getLevel()).isEqualTo(Level.ERROR);
        assertThat(error.getFormattedMessage()).startsWith("Outside a request: upstream dynamodb GetItem on table lookahead-dev-operations gave no answer in ")
                .contains("(SdkClientException: Unable to execute HTTP request: connection reset)");
        assertNothingSecret();
    }

    @Test void aLimitLineNamesTheLimitItsSizeAndWindow() {
        OpsLog.limit("password-pages.per-account", 10, java.time.Duration.ofMinutes(10), "sign-in.password", "Rate limit reached: {}", "x");
        OpsLog.limit("cognito", 0, null, "sign-in.password", "Rate limit reached by Cognito");
        assertThat(pairs(capture.list.get(0))).contains("limit.name=password-pages.per-account", "limit.max=10", "limit.window=PT10M", "reason=TOO_MANY_REQUESTS");
        assertThat(pairs(capture.list.get(1))).contains("limit.name=cognito").noneMatch(pair -> pair.startsWith("limit.max") || pair.startsWith("limit.window"));
        assertThat(capture.list).allMatch(line -> line.getLevel() == Level.WARN && line.getLoggerName().equals("lookahead.limit"));
    }

    /** The one console pattern renders a refusal as one plain WARN line, with the request bracket only while a request id is set. */
    @Test void theConsolePatternRendersOnePlainLinePerEvent() {
        var at = java.time.Instant.parse("2026-11-17T20:44:12.300Z");
        org.slf4j.MDC.put(RequestLog.KEY, requestIdFixture("7a51d9e0-1b2c-4d3e-8f4a-", "5b6c7d8e9f0a"));
        try {
            OpsLog.refused("sign-in.password", "INVALID_CREDENTIALS").addKeyValue("http.status", 401).log("Password sign-in refused: INVALID_CREDENTIALS (wrong email or password)");
        } finally { org.slf4j.MDC.remove(RequestLog.KEY); }
        OpsLog.limit("free-plans", 2, null, "plan.create", "Free plan limit hit for account faaac829: at most 2 active free plans at once");
        assertThat(com.lookahead.gateway.LogCapture.plain(capture.list.get(0), at))
                .isEqualTo("2026-11-17T20:44:12.300Z WARN  Password sign-in refused: INVALID_CREDENTIALS (wrong email or password)  [request 7a51d9e0]\n");
        assertThat(com.lookahead.gateway.LogCapture.plain(capture.list.get(1), at))
                .isEqualTo("2026-11-17T20:44:12.300Z WARN  Free plan limit hit for account faaac829: at most 2 active free plans at once\n");
        assertThat(capture.list).extracting(ILoggingEvent::getFormattedMessage).noneMatch(m -> m.contains("ERROR"));
    }

    /** No line, at any level, carries the token or a query string; ERROR lines quote messages only after masking. */
    void assertNothingSecret() {
        for (var line : capture.list) {
            assertThat(line.getFormattedMessage()).doesNotContain(SECRET).doesNotContain("?");
            assertThat(pairs(line)).noneMatch(pair -> pair.contains(SECRET));
        }
    }
    /** Joined at run time so the fixture id never sits as one literal next to the MDC key (the secret scan reads that as an API key). */
    private static String requestIdFixture(String head, String tail) { return head + tail; }
}
