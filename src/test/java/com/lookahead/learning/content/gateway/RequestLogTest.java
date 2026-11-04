package com.lookahead.learning.content.gateway;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.OutputStreamAppender;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.logging.logback.StructuredLogEncoder;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.ResourceAccessException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** DLV-969 (owner, 2026-11-04): one request ID per request, one summary line, and tidy JSON records in CloudWatch. */
class RequestLogTest {
    private static final String UUID_SHAPE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private final ListAppender<ILoggingEvent> capture = new ListAppender<>();
    private final Logger requests = (Logger) LoggerFactory.getLogger("lookahead.http");
    private final Logger failures = (Logger) LoggerFactory.getLogger(RequestLog.class);
    private final Logger errors = (Logger) LoggerFactory.getLogger(GatewayErrorHandler.class);

    @BeforeEach void listen() {
        capture.start();
        for (Logger logger : List.of(requests, failures, errors)) logger.addAppender(capture);
    }

    @AfterEach void stop() {
        for (Logger logger : List.of(requests, failures, errors)) logger.detachAppender(capture);
        capture.stop();
        MDC.clear();
    }

    private static MockHttpServletResponse run(MockHttpServletRequest request, jakarta.servlet.FilterChain chain) throws Exception {
        var response = new MockHttpServletResponse();
        new RequestLog().doFilter(request, response, chain);
        return response;
    }

    @Test void everyRequestGetsItsOwnIdOnTheLogLinesAndTheAnswerAndNoBrowserIdIsTrusted() throws Exception {
        var seen = new AtomicReference<String>();
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/test-session");
        request.setQueryString("next=/private&token=secret");
        request.addHeader(RequestLog.HEADER, "11111111-2222-4333-8444-555555555555");
        var response = run(request, (req, res) -> {
            seen.set(MDC.get(RequestLog.KEY));
            LoggerFactory.getLogger(RequestLogTest.class).info("inside");
            ((HttpServletResponse) res).setStatus(201);
        });
        assertThat(seen.get()).matches(UUID_SHAPE).isNotEqualTo("11111111-2222-4333-8444-555555555555");
        assertThat(response.getHeader(RequestLog.HEADER)).isEqualTo(seen.get());
        assertThat(MDC.get(RequestLog.KEY)).isNull();
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.INFO);
        assertThat(line.getFormattedMessage()).isEqualTo("POST /bff/api/v1/auth/test-session -> 201 in " + duration(line) + " ms");
        assertThat(line.getMDCPropertyMap()).containsEntry(RequestLog.KEY, seen.get());
        assertThat(pairs(line)).contains("http.method=POST", "url.path=/bff/api/v1/auth/test-session", "http.status=201");
        assertThat(capture.list.toString()).doesNotContain("secret", "next=");
    }

    @Test void serverFailuresWarnAndClientRefusalsStayInfo() throws Exception {
        run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> ((HttpServletResponse) res).setStatus(503));
        run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> ((HttpServletResponse) res).setStatus(401));
        assertThat(capture.list).extracting(ILoggingEvent::getLevel).containsExactly(Level.WARN, Level.INFO);
    }

    @Test void healthChecksAndServedFilesStayQuietButAMissingFileIsLogged() throws Exception {
        run(new MockHttpServletRequest("GET", "/actuator/health/readiness"), (req, res) -> {});
        run(new MockHttpServletRequest("GET", "/health"), (req, res) -> {});
        run(new MockHttpServletRequest("GET", "/assets/main-abc123.js"), (req, res) -> {});
        run(new MockHttpServletRequest("GET", "/assets/gone.js"), (req, res) -> ((HttpServletResponse) res).setStatus(404));
        run(new MockHttpServletRequest("GET", "/learn/java.basics/intro"), (req, res) -> {});
        assertThat(capture.list).extracting(ILoggingEvent::getFormattedMessage)
                .allSatisfy(message -> assertThat(message).doesNotContain("health", "main-abc123"))
                .anySatisfy(message -> assertThat(message).startsWith("GET /assets/gone.js -> 404"))
                // a page whose path has a dot only in an earlier part is still a page, not a file
                .anySatisfy(message -> assertThat(message).startsWith("GET /learn/java.basics/intro -> 200"))
                .hasSize(2);
    }

    @Test void oddMethodsLongPathsAndLineBreaksCannotForgeOrFloodALine() throws Exception {
        run(new MockHttpServletRequest("PROPFIND", "/a\nGET /forged -> 200"), (req, res) -> {});
        run(new MockHttpServletRequest("GET", "/" + "x".repeat(400)), (req, res) -> {});
        assertThat(capture.list.getFirst().getFormattedMessage()).startsWith("OTHER /a_GET /forged -> 200").doesNotContain("\n");
        assertThat(pairs(capture.list.getLast())).contains("url.path=/" + "x".repeat(199) + "…");
    }

    @Test void anEscapedFailureIsLoggedWithItsStackTraceAndTheCallerGetsOnlyTheReference() throws Exception {
        var response = run(new MockHttpServletRequest("POST", "/bff/api/v1/learning/progress"), (req, res) -> {
            ((HttpServletResponse) res).setHeader("X-Partial", "yes");
            throw new IllegalStateException("database password=hunter2 rejected");
        });
        String id = response.getHeader(RequestLog.HEADER);
        assertThat(id).matches(UUID_SHAPE);
        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(response.getHeader("X-Partial")).isNull();
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"UNEXPECTED_ERROR\",\"message\":\"Something went wrong. Quote reference "
                + id + " when you report it.\",\"reference\":\"" + id + "\"}");
        var failure = capture.list.getFirst();
        assertThat(failure.getLevel()).isEqualTo(Level.ERROR);
        assertThat(failure.getFormattedMessage()).isEqualTo("Unexpected failure reference=" + id + " POST /bff/api/v1/learning/progress");
        assertThat(failure.getThrowableProxy().getClassName()).isEqualTo(IllegalStateException.class.getName());
        assertThat(capture.list.getLast().getFormattedMessage()).startsWith("POST /bff/api/v1/learning/progress -> 500");
    }

    @Test void aFailureAfterTheAnswerStartedIsAWarningNotACrash() throws Exception {
        var response = run(new MockHttpServletRequest("GET", "/learn"), (req, res) -> {
            res.getWriter().write("partial page");
            res.flushBuffer();
            throw new IOException("Broken pipe");
        });
        assertThat(response.getContentAsString()).isEqualTo("partial page");
        assertThat(capture.list.getFirst().getLevel()).isEqualTo(Level.WARN);
        assertThat(capture.list.getFirst().getFormattedMessage()).isEqualTo("Request ended early: GET /learn IOException");
        assertThat(capture.list).extracting(ILoggingEvent::getLevel).doesNotContain(Level.ERROR);
    }

    @Test void servletFailuresAreCaughtToo() throws Exception {
        var response = run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> { throw new ServletException("boom"); });
        assertThat(response.getStatus()).isEqualTo(500);
        assertThat(capture.list.getFirst().getLevel()).isEqualTo(Level.ERROR);
    }

    @Test void theIdGoesOnlyToOurOwnUpstreamsAndReplacesAnyOtherValue() throws Exception {
        var interceptor = RequestLog.forwardTo(uri -> uri.getHost().endsWith(".lookahead-dev.internal"));
        var sent = new ArrayList<String>();
        MDC.put(RequestLog.KEY, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        for (String target : List.of("https://domain.lookahead-dev.internal:8443/api/v1/me", "https://auth.example.com/oauth2/token")) {
            var request = new MockClientHttpRequest(HttpMethod.GET, URI.create(target));
            request.getHeaders().add(RequestLog.HEADER, "from-the-browser");
            interceptor.intercept(request, new byte[0], (req, body) -> {
                sent.add(String.valueOf(req.getHeaders().get(RequestLog.HEADER)));
                return mock(ClientHttpResponse.class);
            });
        }
        MDC.clear();
        var outside = new MockClientHttpRequest(HttpMethod.GET, URI.create("https://domain.lookahead-dev.internal:8443/x"));
        interceptor.intercept(outside, new byte[0], (req, body) -> mock(ClientHttpResponse.class));
        assertThat(sent).containsExactly("[aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee]", "[from-the-browser]");
        assertThat(outside.getHeaders().get(RequestLog.HEADER)).isNull();
        assertThat(RequestLog.reference()).matches(UUID_SHAPE);
    }

    @Test void anUnreachableUpstreamIsLoggedWithTheReferenceTheCallerGets() {
        MDC.put(RequestLog.KEY, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        var answer = new GatewayErrorHandler().unavailable(new ResourceAccessException("Bearer secret-token refused",
                new java.net.ConnectException("Connection refused")), new MockHttpServletRequest("GET", "/bff/api/v1/admin/accounts"));
        assertThat(answer.getStatusCode().value()).isEqualTo(503);
        var line = capture.list.getFirst();
        assertThat(line.getLevel()).isEqualTo(Level.WARN);
        assertThat(line.getFormattedMessage()).isEqualTo("Upstream unavailable reference=aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee GET /bff/api/v1/admin/accounts: "
                + "ResourceAccessException < ConnectException");
        assertThat(line.getThrowableProxy()).isNull();
        assertThat(capture.list.toString()).doesNotContain("secret-token");
    }

    @Test void everyFailureSaysItsCodeAndWhyInWords() throws Exception {
        run(new MockHttpServletRequest("POST", "/bff/api/v1/admin/test-accounts/x/delete"), (req, res) -> {
            var answer = (HttpServletResponse) res;
            answer.setStatus(403);
            answer.setContentType("application/json");
            answer.getWriter().write("{\"status\":403,\"code\":\"DELETE_FORBIDDEN\",\"message\":\"Only the owner or the person who created this test account can delete it.\"}");
        });
        run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> ((HttpServletResponse) res).sendError(401, "Full authentication is required"));
        run(new MockHttpServletRequest("POST", "/bff/api/v1/payments/refund"), (req, res) -> ((HttpServletResponse) res).setStatus(501));
        run(new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/sign-in"), (req, res) -> {
            ((HttpServletResponse) res).setStatus(429);
            res.getOutputStream().write("{\"code\":\"TOO_MANY_REQUESTS\",\"message\":\"Too many tries for priya@example.invalid. Wait a minute.\"}".getBytes(StandardCharsets.UTF_8));
        });
        assertThat(capture.list).extracting(ILoggingEvent::getFormattedMessage).map(m -> m.replaceAll(" in \\d+ ms$", "")).containsExactly(
                "POST /bff/api/v1/admin/test-accounts/x/delete -> 403 DELETE_FORBIDDEN: Only the owner or the person who created this test account can delete it.",
                "GET /bff/api/v1/me -> 401 HTTP_401: Full authentication is required",
                "POST /bff/api/v1/payments/refund -> 501 HTTP_501: Not implemented: this action is not available in this environment",
                "POST /bff/api/v1/auth/password/sign-in -> 429 TOO_MANY_REQUESTS: Too many tries for [email]. Wait a minute.");
        assertThat(capture.list).extracting(ILoggingEvent::getLevel).containsExactly(Level.WARN, Level.INFO, Level.WARN, Level.WARN);
        assertThat(pairs(capture.list.getFirst())).contains("error.code=DELETE_FORBIDDEN", "http.status=403");
        assertThat(capture.list.toString()).doesNotContain("priya@");
    }

    @Test void successfulAnswersAreNeverCopiedAndAnErrorBodyIsReadOnlyUpToTheLimit() throws Exception {
        var big = "x".repeat(10_000);
        run(new MockHttpServletRequest("GET", "/learn"), (req, res) -> res.getWriter().write("{\"code\":\"NOT_AN_ERROR\"}" + big));
        run(new MockHttpServletRequest("GET", "/bff/api/v1/plans"), (req, res) -> {
            ((HttpServletResponse) res).setStatus(409);
            res.getWriter().write(big + "{\"code\":\"TOO_LATE\"}");
            res.flushBuffer();
        });
        assertThat(capture.list.getFirst().getFormattedMessage()).doesNotContain("NOT_AN_ERROR");
        assertThat(capture.list.getLast().getFormattedMessage()).contains("409 HTTP_409: Conflict with the current state").doesNotContain("TOO_LATE");
        assertThat(StatusReason.describe(418)).isEqualTo("HTTP 418");
        assertThat(StatusReason.mask("a".repeat(400))).hasSize(301);
    }

    @Test void theWrapperStillWritesEverythingThroughUnchanged() throws Exception {
        var response = run(new MockHttpServletRequest("GET", "/bff/api/v1/x"), (req, res) -> {
            ((HttpServletResponse) res).setStatus(404);
            res.getOutputStream().write('{');
            res.getOutputStream().write("\"code\":\"NO_SUCH_PLAN\"}".getBytes(StandardCharsets.UTF_8), 0, 22);
            res.getOutputStream().flush();
            assertThat(res.getOutputStream().isReady()).isTrue();
        });
        assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"NO_SUCH_PLAN\"}");
        assertThat(capture.list.getLast().getFormattedMessage()).contains("404 NO_SUCH_PLAN: Not found");
    }

    /** The DEV profile's own settings render one JSON record per line, with the request ID, and ERROR stays findable. */
    @Test void theDevProfileWritesOneTidyJsonRecordPerLine() throws Exception {
        var environment = new MockEnvironment();
        for (var source : new YamlPropertySourceLoader().load("dev", new ClassPathResource("application-lower-cost-dev.yml")))
            environment.getPropertySources().addFirst(source);
        var context = (LoggerContext) LoggerFactory.getILoggerFactory();
        Object previous = context.getObject(Environment.class.getName());
        var out = new ByteArrayOutputStream();
        var encoder = new StructuredLogEncoder();
        var appender = new OutputStreamAppender<ILoggingEvent>();
        try {
            context.putObject(Environment.class.getName(), environment);
            encoder.setContext(context);
            encoder.setFormat(environment.getProperty("logging.structured.format.console"));
            encoder.start();
            appender.setContext(context);
            appender.setEncoder(encoder);
            appender.setOutputStream(out);
            appender.start();
            requests.addAppender(appender);
            failures.addAppender(appender);
            var response = run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> {
                throw new IllegalStateException("outer", new IllegalArgumentException("root cause"));
            });
            String id = response.getHeader(RequestLog.HEADER);
            String[] lines = out.toString(StandardCharsets.UTF_8).strip().split("\n");
            assertThat(lines).hasSize(2);
            var mapper = new ObjectMapper();
            JsonNode error = mapper.readTree(lines[0]);
            JsonNode summary = mapper.readTree(lines[1]);
            assertThat(lines[0]).contains("\"ERROR\"");
            assertThat(error.at("/log/level").asString()).isEqualTo("ERROR");
            assertThat(error.at("/service/name").asString()).isEqualTo("gateway");
            assertThat(error.at("/service/environment").asString()).isEqualTo("dev");
            assertThat(error.get(RequestLog.KEY).asString()).isEqualTo(id);
            assertThat(error.at("/error/type").asString()).isEqualTo(IllegalStateException.class.getName());
            String trace = error.at("/error/stack_trace").asString();
            assertThat(trace.indexOf("root cause")).isLessThan(trace.indexOf("outer")).isNotNegative();
            assertThat(summary.at("/log/logger").asString()).isEqualTo("lookahead.http");
            assertThat(summary.get(RequestLog.KEY).asString()).isEqualTo(id);
            assertThat(summary.at("/http/status").isMissingNode() ? summary.get("http.status") : summary.at("/http/status")).isNotNull();
        } finally {
            requests.detachAppender(appender);
            failures.detachAppender(appender);
            appender.stop();
            encoder.stop();
            if (previous != null) context.putObject(Environment.class.getName(), previous);
        }
    }

    private static String duration(ILoggingEvent line) {
        return pairs(line).stream().filter(pair -> pair.startsWith("durationMs=")).findFirst().orElseThrow().substring(11);
    }

    private static List<String> pairs(ILoggingEvent line) {
        return line.getKeyValuePairs() == null ? List.of() : line.getKeyValuePairs().stream().map(pair -> pair.key + "=" + pair.value).toList();
    }
}
