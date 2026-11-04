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

/** DLV-969 (owner, 2026-11-04): one upstream line per outbound call and per AWS call, every SDK retry, and no secrets. */
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
        // An upstream 5xx is WARN.
        var down = call(HttpMethod.POST, "https://domain.lookahead-dev.internal:8443/internal/v1/cloud-sign-ins/admit", answer(HttpStatus.SERVICE_UNAVAILABLE));
        assertThat(down.getLevel()).isEqualTo(Level.WARN);
        assertThat(down.getFormattedMessage()).startsWith("Upstream domain POST /internal/v1/cloud-sign-ins/admit -> 503 in ");
        // Cognito's hosts, the local Identity and anything else.
        assertThat(pairs(call(HttpMethod.POST, "https://example.auth.us-east-2.amazoncognito.com/oauth2/revoke", answer(HttpStatus.OK)))).contains("upstream.service=cognito");
        assertThat(pairs(call(HttpMethod.GET, "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example/.well-known/jwks.json", answer(HttpStatus.OK)))).contains("upstream.service=cognito");
        assertThat(pairs(call(HttpMethod.GET, "http://identity:9000/userinfo", answer(HttpStatus.OK)))).contains("upstream.service=identity");
        assertThat(pairs(call(HttpMethod.GET, "https://domain.lookahead-dev.internal:9443/x", answer(HttpStatus.OK)))).contains("upstream.service=other");
        assertThat(pairs(call(HttpMethod.GET, "http://localhost/x", answer(HttpStatus.OK)))).contains("upstream.service=other");
    }

    @Test void noAnswerIsAWarningWithTheFailureTypesAndTheFailureIsRethrown() {
        var request = new MockClientHttpRequest(HttpMethod.GET, URI.create("https://domain.lookahead-dev.internal:8443/api/v1/auth/me?code=" + SECRET));
        ClientHttpRequestExecution refused = (sent, body) -> { throw new java.net.ConnectException("Connection refused " + SECRET); };
        assertThatThrownBy(() -> OpsLog.upstream(SERVICES).intercept(request, new byte[0], refused)).isInstanceOf(java.net.ConnectException.class);
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.WARN);
        assertThat(line.getFormattedMessage()).matches("Upstream domain GET /api/v1/auth/me failed after \\d+ ms with no answer \\(NO_RESPONSE\\): ConnectException");
        ClientHttpRequestExecution slow = (sent, body) -> { throw new java.net.http.HttpTimeoutException("request timed out"); };
        assertThatThrownBy(() -> OpsLog.upstream(SERVICES).intercept(request, new byte[0], slow)).isInstanceOf(java.net.http.HttpTimeoutException.class);
        assertThat(pairs(capture.list.getLast())).contains("reason=TIMEOUT", "event.outcome=failure");
        assertNothingSecret();
    }

    @Test void awsCallsLogTheOperationOutcomeAndErrorCodeButNeverTheMessage() {
        assertThat(OpsLog.aws("cognito", "InitiateAuth", () -> "ok")).isEqualTo("ok");
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.INFO);
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Upstream cognito InitiateAuth succeeded in \\d+ ms");
        assertThat(OpsLog.aws("dynamodb", "GetItem", true, () -> "ok")).isEqualTo("ok");
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.DEBUG);

        var refused = NotAuthorizedException.builder().message("Incorrect username or password for priya@example.invalid").statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("NotAuthorizedException").errorMessage(SECRET).build()).build();
        assertThatThrownBy(() -> OpsLog.aws("cognito", "InitiateAuth", () -> { throw refused; })).isSameAs(refused);
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.INFO);
        assertThat(line.getFormattedMessage()).matches("Upstream cognito InitiateAuth -> 400 NotAuthorizedException in \\d+ ms");
        assertThat(pairs(line)).contains("upstream.service=cognito", "upstream.operation=InitiateAuth", "upstream.status=400",
                "upstream.code=NotAuthorizedException", "event.outcome=failure");

        var broken = InternalErrorException.builder().statusCode(500).build();
        assertThatThrownBy(() -> OpsLog.aws("cognito", "SignUp", () -> { throw broken; })).isSameAs(broken);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.WARN);
        assertThat(pairs(capture.list.getLast())).contains("upstream.code=InternalErrorException");

        var offline = SdkClientException.create("Unable to execute HTTP request " + SECRET);
        assertThatThrownBy(() -> OpsLog.aws("cognito", "AdminGetUser", () -> { throw offline; })).isSameAs(offline);
        assertThat(capture.list.getLast().getLevel()).isEqualTo(Level.WARN);
        assertThat(capture.list.getLast().getFormattedMessage()).matches("Upstream cognito AdminGetUser failed after \\d+ ms with no answer: SdkClientException");
        assertNothingSecret();
        assertThat(capture.list).extracting(ILoggingEvent::getFormattedMessage).noneMatch(m -> m.contains("priya@example.invalid"));
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

    @Test void anUnreadableStatusTableIsLoggedAsAFailureWithItsTypes() {
        var client = org.mockito.Mockito.mock(DynamoDbClient.class);
        org.mockito.Mockito.when(client.getItem(org.mockito.ArgumentMatchers.<java.util.function.Consumer<software.amazon.awssdk.services.dynamodb.model.GetItemRequest.Builder>>any()))
                .thenThrow(SdkClientException.create("down " + SECRET));
        assertThat(new DevSessionStatus(client, "t").status().getStatusCode().value()).isEqualTo(503);
        assertThat(capture.list.getLast().getFormattedMessage()).isEqualTo("DEV session status unavailable: the operations table could not be read (SdkClientException)");
        assertThat(pairs(capture.list.getLast())).contains("event.action=dev-session.status", "event.outcome=failure", "reason=DEV_STATUS_UNAVAILABLE");
        assertNothingSecret();
    }

    @Test void aLimitLineNamesTheLimitItsSizeAndWindow() {
        OpsLog.limit("password-pages.per-account", 10, java.time.Duration.ofMinutes(10), "sign-in.password", "Rate limit reached: {}", "x");
        OpsLog.limit("cognito", 0, null, "sign-in.password", "Rate limit reached by Cognito");
        assertThat(pairs(capture.list.get(0))).contains("limit.name=password-pages.per-account", "limit.max=10", "limit.window=PT10M", "reason=TOO_MANY_REQUESTS");
        assertThat(pairs(capture.list.get(1))).contains("limit.name=cognito").noneMatch(pair -> pair.startsWith("limit.max") || pair.startsWith("limit.window"));
        assertThat(capture.list).allMatch(line -> line.getLevel() == Level.WARN && line.getLoggerName().equals("lookahead.limit"));
    }

    /** The DEV profile's ECS encoder renders the keys as queryable JSON members, one record per line. */
    @Test void theDevProfileRendersTheKeysAsJson() throws Exception {
        var environment = new MockEnvironment();
        for (var source : new org.springframework.boot.env.YamlPropertySourceLoader().load("dev", new org.springframework.core.io.ClassPathResource("application-lower-cost-dev.yml")))
            environment.getPropertySources().addFirst(source);
        var context = (ch.qos.logback.classic.LoggerContext) LoggerFactory.getILoggerFactory();
        Object previous = context.getObject(org.springframework.core.env.Environment.class.getName());
        var out = new java.io.ByteArrayOutputStream();
        var encoder = new org.springframework.boot.logging.logback.StructuredLogEncoder();
        var appender = new ch.qos.logback.core.OutputStreamAppender<ILoggingEvent>();
        var events = (Logger) LoggerFactory.getLogger("lookahead.event");
        try {
            context.putObject(org.springframework.core.env.Environment.class.getName(), environment);
            encoder.setContext(context); encoder.setFormat(environment.getProperty("logging.structured.format.console")); encoder.start();
            appender.setContext(context); appender.setEncoder(encoder); appender.setOutputStream(out); appender.start();
            events.addAppender(appender);
            OpsLog.refused("sign-in.password", "INVALID_CREDENTIALS").addKeyValue("http.status", 401).log("Password sign-in refused: INVALID_CREDENTIALS");
        } finally {
            events.detachAppender(appender); appender.stop(); encoder.stop();
            if (previous != null) context.putObject(org.springframework.core.env.Environment.class.getName(), previous);
        }
        String[] lines = out.toString(StandardCharsets.UTF_8).strip().split("\n");
        assertThat(lines).hasSize(1);
        var json = new tools.jackson.databind.ObjectMapper().readTree(lines[0]);
        assertThat(json.at("/log/level").asString()).isEqualTo("WARN");
        assertThat(json.at("/log/logger").asString()).isEqualTo("lookahead.event");
        assertThat(json.get("message").asString()).isEqualTo("Password sign-in refused: INVALID_CREDENTIALS");
        var action = json.at("/event/action").isMissingNode() ? json.get("event.action") : json.at("/event/action");
        var reason = json.get("reason");
        assertThat(action.asString()).isEqualTo("sign-in.password");
        assertThat(reason.asString()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(lines[0]).doesNotContain("ERROR");
    }

    void assertNothingSecret() {
        for (var line : capture.list) {
            assertThat(line.getFormattedMessage()).doesNotContain(SECRET).doesNotContain("?");
            assertThat(pairs(line)).noneMatch(pair -> pair.contains(SECRET));
            assertThat(line.getLevel()).isNotEqualTo(Level.ERROR);
        }
    }
}
