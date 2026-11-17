package com.lookahead.learning.content.gateway;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * DLV-969 (owner, 2026-11-04): every browser request gets one request ID. It is on every log line written while the
 * request runs (the plain pattern renders it as {@code [request <first 8 characters>]}), goes to Domain and Web as
 * {@code X-Request-Id}, and comes back to the browser, so one search in CloudWatch shows the whole request. Each request
 * also writes one summary line: method, path (never the query), status and time taken, and for every 4xx and 5xx its
 * code and the reason in words ({@link StatusReason}). 403, 429 and 5xx are WARN. Health checks and successful static
 * files stay quiet.
 *
 * <p>Plain logs (owner decision 2026-11-17): a request that hit a failure an operator must act on ends with one ERROR
 * line per failure instead of the summary. Each says what was being done (the request), what failed (the upstream
 * service, operation and host or resource, the exception type and its message, the HTTP status), what the browser got
 * (status and code), the reference next to the stack trace that follows, and a hint where the code knows the cause.
 * Upstream failures are recorded while the request runs ({@link #upstreamFailed}) and written here, where the answer is
 * known. A failure that escapes everything else is the same kind of line, with {@code UNEXPECTED_ERROR}; the caller gets
 * the request ID as its reference and nothing else.
 */
@Component @Order(Ordered.HIGHEST_PRECEDENCE)
public final class RequestLog extends OncePerRequestFilter {
    static final String HEADER = "X-Request-Id";
    static final String KEY = "requestId";
    private static final Logger requests = LoggerFactory.getLogger("lookahead.http");
    private static final Logger failures = LoggerFactory.getLogger(RequestLog.class);
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");
    private static final ThreadLocal<Frame> FRAME = new ThreadLocal<>();

    /** The request this thread is serving and what failed while serving it. */
    private static final class Frame {
        final String method, path;
        final List<OpsLog.Failure> upstream = new ArrayList<>();
        Exception unexpected;
        Frame(String method, String path) { this.method = method; this.path = path; }
    }

    /** The request ID of the request this thread is serving, or a new one outside a request. */
    static String reference() {
        String id = MDC.get(KEY);
        return id != null ? id : UUID.randomUUID().toString();
    }

    /**
     * Records an upstream failure for the ERROR line at the end of this request. Outside a request (no filter frame on
     * this thread) the line is written at once, without an answer to report.
     */
    static void upstreamFailed(OpsLog.Failure failure) {
        Frame frame = FRAME.get();
        if (frame != null) { frame.upstream.add(failure); return; }
        var line = failure.keys(OpsLog.UPSTREAM.atError());
        String sentence = "Outside a request: " + failure.words();
        if (failure.cause() != null) {
            String reference = reference();
            line = line.setCause(failure.cause());
            sentence += "; reference " + reference;
        }
        if (failure.hint() != null) sentence += "; " + failure.hint();
        line.log(sentence);
    }

    /** True while an upstream failure is already recorded for the request this thread serves. */
    static boolean upstreamFailurePending() {
        Frame frame = FRAME.get();
        return frame != null && !frame.upstream.isEmpty();
    }

    /** Passes the request ID on to the upstreams {@code upstream} accepts, replacing anything the browser sent. */
    static ClientHttpRequestInterceptor forwardTo(Predicate<URI> upstream) {
        return (request, body, execution) -> {
            String id = MDC.get(KEY);
            if (id != null && upstream.test(request.getURI())) request.getHeaders().set(HEADER, id);
            return execution.execute(request, body);
        };
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String id = UUID.randomUUID().toString();
        long started = System.nanoTime();
        MDC.put(KEY, id);
        response.setHeader(HEADER, id);
        var watched = new StatusReason(response);
        var frame = new Frame(method(request), path(request));
        FRAME.set(frame);
        StatusReason.Reason reason = null;
        try {
            chain.doFilter(request, watched);
            reason = watched.reason();
        } catch (IOException | ServletException | RuntimeException failure) {
            reason = failed(request, response, id, failure, frame);
        } finally {
            summary(frame, response.getStatus(), (System.nanoTime() - started) / 1_000_000, reason, watched.reference(), id);
            FRAME.remove();
            MDC.remove(KEY);
        }
    }

    private static StatusReason.Reason failed(HttpServletRequest request, HttpServletResponse response, String id, Exception failure, Frame frame)
            throws IOException {
        if (response.isCommitted()) {
            // The answer was already on its way; usually the browser left. Nothing can be sent, so no ERROR.
            failures.warn("Request ended early: {} {} {}", method(request), path(request), types(failure));
            return response.getStatus() >= 400 ? new StatusReason.Reason("HTTP_" + response.getStatus(), StatusReason.describe(response.getStatus())) : null;
        }
        frame.unexpected = failure;
        response.reset();
        response.setHeader(HEADER, id);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(500);
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":\"UNEXPECTED_ERROR\",\"message\":\"Something went wrong. Quote reference "
                + id + " when you report it.\",\"reference\":\"" + id + "\"}");
        return new StatusReason.Reason("UNEXPECTED_ERROR", types(failure) + " at " + where(failure));
    }

    /**
     * Successes: "GET /x -> 200 in 3 ms". Failures add the code and why: "POST /x -> 403 DELETE_FORBIDDEN: Only the owner… in
     * 9 ms". A request with an upstream or unexpected failure writes ERROR lines instead ({@link #error}).
     */
    private static void summary(Frame frame, int status, long millis, StatusReason.Reason reason, String answerReference, String id) {
        if (frame.unexpected == null && frame.upstream.isEmpty()) {
            if (quiet(frame.path, status)) return;
            var line = (status >= 500 || status == 403 || status == 429 ? requests.atWarn() : requests.atInfo())
                    .addKeyValue("http.method", frame.method).addKeyValue("url.path", frame.path)
                    .addKeyValue("http.status", status).addKeyValue("durationMs", millis);
            if (reason == null) {
                line.log("{} {} -> {} in {} ms", frame.method, frame.path, status, millis);
                return;
            }
            line.addKeyValue("error.code", reason.code()).addKeyValue("error.reason", reason.words())
                    .log("{} {} -> {} {}: {} in {} ms", frame.method, frame.path, status, reason.code(), reason.words(), millis);
            return;
        }
        for (var failure : frame.upstream) {
            // No stack trace for a 5xx answer: the reference is then the one the upstream's own answer carried, if any.
            String reference = failure.cause() != null ? id : answerReference != null && !answerReference.equals(id)
                    ? answerReference + " (from the upstream's answer: its own ERROR line carries the same)" : null;
            error(failure.keys(OpsLog.UPSTREAM.atError()), frame, status, millis, reason, failure.words(), failure.cause(), reference, failure.hint());
        }
        if (frame.unexpected != null) {
            var line = failures.atError().addKeyValue("exception.types", types(frame.unexpected));
            error(line, frame, status, millis, reason, "unexpected " + types(frame.unexpected) + " in " + where(frame.unexpected) + ": "
                    + OpsLog.safe(message(frame.unexpected)), frame.unexpected, id, null);
        }
    }

    /**
     * One ERROR line: "POST /x failed after 41 ms: {what failed}; answered 503 SERVICE_UNAVAILABLE; reference …; {hint}".
     * When the request still answered below 500 the line says so instead: "GET /x -> 200 in 50 ms, but {what failed}; the
     * request was answered without it".
     */
    private static void error(LoggingEventBuilder line, Frame frame, int status, long millis, StatusReason.Reason reason, String what,
            Throwable cause, String reference, String hint) {
        String code = reason == null ? "" : " " + reason.code();
        String sentence = status >= 500
                ? frame.method + " " + frame.path + " failed after " + millis + " ms: " + what + "; answered " + status + code
                : frame.method + " " + frame.path + " -> " + status + code + " in " + millis + " ms, but " + what + "; the request was answered without it";
        if (reference != null) sentence += "; reference " + reference;
        if (hint != null) sentence += "; " + hint;
        line = line.addKeyValue("http.method", frame.method).addKeyValue("url.path", frame.path)
                .addKeyValue("http.status", status).addKeyValue("durationMs", millis);
        if (reason != null) line = line.addKeyValue("error.code", reason.code()).addKeyValue("error.reason", reason.words());
        if (cause != null) line = line.setCause(cause);
        line.log(sentence);
    }

    static boolean quiet(String path, int status) {
        if (path.startsWith("/actuator/") || path.equals("/health")) return true;
        String last = path.substring(path.lastIndexOf('/') + 1);
        return status < 400 && last.contains(".");
    }

    /** The exception and its causes by type only, e.g. "ResourceAccessException < ConnectException". */
    static String types(Throwable failure) {
        var names = new java.util.ArrayList<String>();
        for (Throwable at = failure; at != null && names.size() < 5; at = at.getCause()) names.add(at.getClass().getSimpleName());
        return String.join(" < ", names);
    }

    /** The exception's own message, else the innermost cause's. */
    static String message(Throwable failure) {
        String message = failure.getMessage();
        for (Throwable at = failure.getCause(); at != null && (message == null || message.isBlank()); at = at.getCause()) message = at.getMessage();
        return message;
    }

    /** Where the failure was thrown: the first frame in our own code, "PlanService.publish (PlanService.java:148)", else the top frame. */
    static String where(Throwable failure) {
        StackTraceElement[] trace = failure.getStackTrace();
        if (trace == null || trace.length == 0) return "an unknown place";
        StackTraceElement frame = trace[0];
        for (StackTraceElement at : trace) if (at.getClassName().startsWith("com.lookahead.")) { frame = at; break; }
        String type = frame.getClassName().substring(frame.getClassName().lastIndexOf('.') + 1);
        return type + "." + frame.getMethodName() + " (" + frame.getFileName() + ":" + frame.getLineNumber() + ")";
    }

    static String method(HttpServletRequest request) {
        return METHODS.contains(request.getMethod()) ? request.getMethod() : "OTHER";
    }

    /** The path only: never the query, at most 200 characters, and no line breaks to forge a second line. */
    static String path(HttpServletRequest request) {
        String path = request.getRequestURI() == null ? "" : request.getRequestURI().replaceAll("[\\r\\n\\t]", "_");
        return path.length() > 200 ? path.substring(0, 200) + "…" : path;
    }
}
