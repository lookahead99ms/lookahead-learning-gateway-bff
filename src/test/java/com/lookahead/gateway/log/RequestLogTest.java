package com.lookahead.gateway.log;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxy;
import ch.qos.logback.core.read.ListAppender;
import com.lookahead.gateway.security.handler.UpstreamErrorHandler;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpConnectTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DLV-969 (owner, 2026-11-04): one request ID per request, one summary line. Plain logs (2026-11-17): a request that hit an
 * upstream or unexpected failure ends with one ERROR line per failure that says what failed, what the browser got and
 * where the stack trace is; the console pattern renders every line as one plain sentence with the request bracket.
 * The response wrapper that keeps the reason has its own cases in RequestStatusReasonTest.
 */
class RequestLogTest {
    private static final String UUID_SHAPE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final Instant AT = Instant.parse("2026-11-17T20:41:18.144Z");
    private static final Function<URI, String> SERVICES = OpsLog.services(new MockEnvironment()
            .withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443"));
    private final ListAppender<ILoggingEvent> capture = new ListAppender<>();
    private final Logger requests = (Logger) LoggerFactory.getLogger("lookahead.http");
    private final Logger failures = (Logger) LoggerFactory.getLogger(RequestLog.class);
    private final Logger upstream = (Logger) LoggerFactory.getLogger("lookahead.upstream");

    @BeforeEach void listen() {
        capture.start();
        for (Logger logger : List.of(requests, failures, upstream)) logger.addAppender(capture);
    }

    @AfterEach void stop() {
        for (Logger logger : List.of(requests, failures, upstream)) logger.detachAppender(capture);
        capture.stop();
        MDC.clear();
    }

    private static MockHttpServletResponse run(MockHttpServletRequest request, FilterChain chain) throws Exception {
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
        // One ERROR line replaces the summary: the request, where it failed, the masked message, the answer, the reference.
        assertThat(capture.list).hasSize(1);
        var failure = capture.list.getFirst();
        assertThat(failure.getLevel()).isEqualTo(Level.ERROR);
        assertThat(failure.getFormattedMessage()).matches("POST /bff/api/v1/learning/progress failed after \\d+ ms: unexpected IllegalStateException in "
                + "RequestLogTest\\.lambda\\$\\S+ \\(RequestLogTest\\.java:\\d+\\): database password=\\[hidden\\] rejected; answered 500 UNEXPECTED_ERROR; reference " + id);
        assertThat(failure.getFormattedMessage()).doesNotContain("hunter2");
        assertThat(failure.getThrowableProxy().getClassName()).isEqualTo(IllegalStateException.class.getName());
        assertThat(pairs(failure)).contains("http.method=POST", "url.path=/bff/api/v1/learning/progress", "http.status=500", "error.code=UNEXPECTED_ERROR",
                "exception.types=IllegalStateException");
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

    /** Runs {@code call} through the outbound interceptor as the request's controller would, answering 503 SERVICE_UNAVAILABLE on any failure. */
    private static MockHttpServletResponse viaUpstream(MockHttpServletRequest request, String target, FilterChain afterwards,
            ClientHttpRequestExecution execution) throws Exception {
        return run(request, (req, res) -> {
            var outbound = new MockClientHttpRequest(HttpMethod.valueOf(request.getMethod()), URI.create(target));
            try {
                var answer = OpsLog.upstream(SERVICES).intercept(outbound, new byte[0], execution);
                afterwards.doFilter(req, res);
                if (answer.getStatusCode().is5xxServerError()) {
                    ((HttpServletResponse) res).setStatus(503);
                    res.getWriter().write(new String(answer.getBody().readAllBytes(), StandardCharsets.UTF_8));
                }
            } catch (IOException noAnswer) {
                var unavailable = new UpstreamErrorHandler().unavailable(new ResourceAccessException("I/O error on GET request", noAnswer), request);
                ((HttpServletResponse) res).setStatus(unavailable.getStatusCode().value());
                res.getWriter().write("{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"The account service is temporarily unavailable. Retry shortly.\"}");
            }
        });
    }

    @Test void anUnreachableUpstreamIsOneErrorLineWithTheRequestTheHostTheCauseTheAnswerTheReferenceAndAHint() throws Exception {
        var response = viaUpstream(new MockHttpServletRequest("GET", "/bff/api/v1/admin/accounts"), "https://domain.lookahead-dev.internal:8443/api/v1/admin/accounts?token=secret-token",
                (req, res) -> {}, (sent, body) -> { throw new ConnectException("Connection refused"); });
        String id = response.getHeader(RequestLog.HEADER);
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(capture.list).hasSize(1);
        var line = capture.list.getFirst();
        assertThat(line.getLevel()).isEqualTo(Level.ERROR);
        assertThat(line.getLoggerName()).isEqualTo("lookahead.upstream");
        assertThat(line.getFormattedMessage()).matches("GET /bff/api/v1/admin/accounts failed after \\d+ ms: upstream domain GET /api/v1/admin/accounts at "
                + "domain\\.lookahead-dev\\.internal:8443 gave no answer in \\d+ ms \\(ConnectException: Connection refused\\); answered 503 SERVICE_UNAVAILABLE; reference " + id
                + "; nothing accepted the connection: check that the domain task is running, its Cloud Map name points at a live task and its security group allows the Gateway");
        assertThat(line.getThrowableProxy().getClassName()).isEqualTo(ConnectException.class.getName());
        assertThat(line.getMDCPropertyMap()).containsEntry(RequestLog.KEY, id);
        assertThat(pairs(line)).contains("upstream.service=domain", "upstream.operation=GET /api/v1/admin/accounts", "reason=NO_RESPONSE", "http.status=503",
                "error.code=SERVICE_UNAVAILABLE", "durationMs=" + duration(line));
        assertThat(capture.list.toString()).doesNotContain("secret-token");
    }

    @Test void aDomainServerErrorRelayedToTheBrowserCarriesDomainsReferenceSoOneSearchFindsBothLines() throws Exception {
        String domainReference = "7f1a2c3d-aaaa-4bbb-8ccc-dddddddddddd";
        byte[] body = ("{\"code\":\"ACCOUNT_STORAGE_UNAVAILABLE\",\"message\":\"Plans cannot be saved right now.\",\"reference\":\"" + domainReference + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        var response = viaUpstream(new MockHttpServletRequest("POST", "/bff/api/v1/plans"), "https://domain.lookahead-dev.internal:8443/api/v1/plans",
                (req, res) -> {}, (sent, sentBody) -> new MockClientHttpResponse(body, HttpStatus.SERVICE_UNAVAILABLE));
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(capture.list).hasSize(1);
        var line = capture.list.getFirst();
        assertThat(line.getLevel()).isEqualTo(Level.ERROR);
        assertThat(line.getFormattedMessage()).matches("POST /bff/api/v1/plans failed after \\d+ ms: upstream domain POST /api/v1/plans at domain\\.lookahead-dev\\.internal:8443 "
                + "answered 503 in \\d+ ms; answered 503 ACCOUNT_STORAGE_UNAVAILABLE; reference " + domainReference + " \\(from the upstream's answer: its own ERROR line carries the same\\); "
                + "the domain answered a server error; its own log has the detail");
        assertThat(line.getThrowableProxy()).isNull();  // the upstream answered: no stack trace, so the reference is Domain's
        assertThat(pairs(line)).contains("upstream.status=503", "reason=HTTP_503", "error.code=ACCOUNT_STORAGE_UNAVAILABLE");
    }

    @Test void anUpstreamFailureTheRequestSurvivedIsStillAnErrorSayingTheRequestWasAnsweredWithoutIt() throws Exception {
        var response = viaUpstream(new MockHttpServletRequest("GET", "/learn"), "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example/.well-known/jwks.json",
                (req, res) -> {}, (sent, body) -> { throw new HttpConnectTimeoutException("HTTP connect timed out"); });
        // The chain above answered 503; this request's own code swallowed the failure instead: simulate by a chain that catches it.
        var survived = run(new MockHttpServletRequest("GET", "/learn"), (req, res) -> {
            var outbound = new MockClientHttpRequest(HttpMethod.GET, URI.create("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example/.well-known/jwks.json"));
            try { OpsLog.upstream(SERVICES).intercept(outbound, new byte[0], (sent, body) -> { throw new HttpConnectTimeoutException("HTTP connect timed out"); }); }
            catch (IOException ignored) { ((HttpServletResponse) res).setStatus(200); }
        });
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(survived.getStatus()).isEqualTo(200);
        var line = capture.list.getLast();
        assertThat(line.getLevel()).isEqualTo(Level.ERROR);
        assertThat(line.getFormattedMessage()).matches("GET /learn -> 200 in \\d+ ms, but upstream cognito GET /us-east-2_Example/.well-known/jwks.json at cognito-idp\\.us-east-2\\.amazonaws\\.com "
                + "gave no answer in \\d+ ms \\(HttpConnectTimeoutException: HTTP connect timed out\\); the request was answered without it; reference " + survived.getHeader(RequestLog.HEADER)
                + "; a connect failure to an AWS endpoint from the task's subnet usually means the VPC endpoint or its security group does not let the Gateway through");
        assertThat(pairs(line)).contains("reason=TIMEOUT", "http.status=200");
    }

    @Test void aRestClientFailureThatDidNotComeThroughTheInterceptorIsRecordedByTheHandlerWithItsTypeAndMessage() throws Exception {
        var response = run(new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/sign-in"), (req, res) -> {
            var unavailable = new UpstreamErrorHandler().unavailable(new RestClientException("Invalid Domain response"), (MockHttpServletRequest) req);
            ((HttpServletResponse) res).setStatus(unavailable.getStatusCode().value());
            res.getWriter().write("{\"code\":\"SERVICE_UNAVAILABLE\"}");
        });
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(capture.list).hasSize(1);
        assertThat(capture.list.getFirst().getLevel()).isEqualTo(Level.ERROR);
        assertThat(capture.list.getFirst().getFormattedMessage()).matches("POST /bff/api/v1/auth/password/sign-in failed after \\d+ ms: the upstream call for "
                + "POST /bff/api/v1/auth/password/sign-in failed \\(RestClientException: Invalid Domain response\\); answered 503 SERVICE_UNAVAILABLE; reference " + response.getHeader(RequestLog.HEADER));
        assertThat(capture.list.getFirst().getThrowableProxy().getClassName()).isEqualTo(RestClientException.class.getName());
        assertThat(RequestLog.upstreamFailurePending()).isFalse();  // the frame is gone with the request
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

    /**
     * The real console pattern (application.yml) renders each line as "timestamp level sentence  [request id8]": an INFO
     * summary, a WARN refusal, and an ERROR with its stack trace on the lines after it. WARN and INFO lines never say ERROR.
     */
    @Test void theConsolePatternRendersPlainLinesWithTheRequestBracketAndTheStackTraceUnderAnError() throws Exception {
        var ok = run(new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/sign-in"), (req, res) -> ((HttpServletResponse) res).setStatus(200));
        var refused = run(new MockHttpServletRequest("POST", "/bff/api/v1/admin/test-accounts/x/delete"), (req, res) -> {
            ((HttpServletResponse) res).setStatus(403);
            res.getWriter().write("{\"code\":\"DELETE_FORBIDDEN\",\"message\":\"Only the owner can delete it.\"}");
        });
        var failed = run(new MockHttpServletRequest("GET", "/bff/api/v1/me"), (req, res) -> {
            throw new IllegalStateException("outer", new IllegalArgumentException("root cause"));
        });
        assertThat(capture.list).hasSize(3);
        var summary = capture.list.get(0);
        assertThat(LogCapture.plain(summary, AT)).isEqualTo("2026-11-17T20:41:18.144Z INFO  POST /bff/api/v1/auth/password/sign-in -> 200 in " + duration(summary)
                + " ms  [request " + ok.getHeader(RequestLog.HEADER).substring(0, 8) + "]\n");
        var warning = capture.list.get(1);
        assertThat(LogCapture.plain(warning, AT)).isEqualTo("2026-11-17T20:41:18.144Z WARN  POST /bff/api/v1/admin/test-accounts/x/delete -> 403 DELETE_FORBIDDEN: Only the owner can delete it. in "
                + duration(warning) + " ms  [request " + refused.getHeader(RequestLog.HEADER).substring(0, 8) + "]\n");
        var error = capture.list.get(2);
        String id = failed.getHeader(RequestLog.HEADER);
        String rendered = LogCapture.plain(error, AT);
        String[] lines = rendered.split("\n");
        var thrown = ((ThrowableProxy) error.getThrowableProxy()).getThrowable();
        assertThat(lines[0]).isEqualTo("2026-11-17T20:41:18.144Z ERROR GET /bff/api/v1/me failed after " + duration(error) + " ms: unexpected IllegalStateException < IllegalArgumentException in "
                + OpsLog.where(thrown) + ": outer; answered 500 UNEXPECTED_ERROR; reference " + id + "  [request " + id.substring(0, 8) + "]");
        assertThat(lines[1]).isEqualTo("java.lang.IllegalStateException: outer");
        assertThat(lines[2]).startsWith("\tat ");
        assertThat(rendered).contains("\nCaused by: java.lang.IllegalArgumentException: root cause\n");
        // A line logged outside any request has no bracket and no trailing spaces.
        requests.info("Cognito GetUser succeeded in 21 ms");
        assertThat(LogCapture.plain(capture.list.get(3), AT)).isEqualTo("2026-11-17T20:41:18.144Z INFO  Cognito GetUser succeeded in 21 ms\n");
        for (var line : capture.list) if (line.getLevel() != Level.ERROR) assertThat(LogCapture.plain(line, AT)).doesNotContain("ERROR").doesNotEndWith(" \n");
    }

    private static String duration(ILoggingEvent line) {
        return pairs(line).stream().filter(pair -> pair.startsWith("durationMs=")).findFirst().orElseThrow().substring(11);
    }

    private static List<String> pairs(ILoggingEvent line) {
        return line.getKeyValuePairs() == null ? List.of() : line.getKeyValuePairs().stream().map(pair -> pair.key + "=" + pair.value).toList();
    }
}
