package com.lookahead.gateway.log;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.MDC;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * DLV-969 (owner, 2026-11-04): every browser request gets one request ID. It is on every log line written while the
 * request runs (the plain pattern renders it as {@code [request <first 8 characters>]}), goes to Domain and Web as
 * {@code X-Request-Id}, and comes back to the browser, so one search in CloudWatch shows the whole request. Each request
 * also writes one summary line: method, path (never the query), status and time taken, and for every 4xx and 5xx its
 * code and the reason in words ({@link RequestStatusReason}, the response wrapper beside this class, which reads the
 * start of an error answer as it is written). 403, 429 and 5xx are WARN. Health checks and successful static files
 * stay quiet.
 *
 * <p>Plain logs (owner decision 2026-11-17): a request that hit a failure an operator must act on ends with one ERROR
 * line per failure instead of the summary. Each says what was being done (the request), what failed (the upstream
 * service, operation and host or resource, the exception type and its message, the HTTP status), what the browser got
 * (status and code), the reference next to the stack trace that follows, and a hint where the code knows the cause.
 * Upstream failures are recorded while the request runs ({@link #upstreamFailed}) and written here, where the answer is
 * known. A failure that escapes everything else is the same kind of line, with {@code UNEXPECTED_ERROR}; the caller gets
 * the request ID as its reference and nothing else.
 *
 * <p>The two loggers these lines are written on are declared in {@link OpsLog}, with the names they always had:
 * {@code lookahead.http} for the summary line ({@code OpsLog.HTTP}) and this class's own name for the two lines about a
 * request that ended early or failed unexpectedly ({@code OpsLog.REQUEST}).
 *
 * <p>Exception, decided 2026-11-25 (DLV-1015): besides writing the finished-request line this class creates the request
 * ID and sets its header, and writes the 500 {@code UNEXPECTED_ERROR} answer for an unhandled error (rule 5: one
 * responsibility per class); and it is a servlet filter that lives in {@code log} (rule 1: packages by layer). All of
 * it needs the outermost position: the ID has to exist before any other line of the request is written, and the answer
 * covers whatever other filters, Spring Security and every controller let through, with the headers set so far cleared
 * first; a handler class sees only what a controller method throws and answers through Spring MVC, so the same status,
 * headers and body cannot be kept.
 */
@Component @Order(Ordered.HIGHEST_PRECEDENCE)
public final class RequestLog extends OncePerRequestFilter {
    public static final String HEADER = "X-Request-Id";
    public static final String KEY = "requestId";
    private static final ThreadLocal<Frame> FRAME = new ThreadLocal<>();

    /** The request this thread is serving and what failed while serving it. */
    private static final class Frame {
        final String method, path;
        final List<OpsLog.Failure> upstream = new ArrayList<>();
        Exception unexpected;
        Frame(String method, String path) { this.method = method; this.path = path; }
    }

    /** The request ID of the request this thread is serving, or a new one outside a request. */
    public static String reference() {
        String id = MDC.get(KEY);
        return id != null ? id : UUID.randomUUID().toString();
    }

    /**
     * Records an upstream failure for the ERROR line at the end of this request. Outside a request (no filter frame on
     * this thread) the line is written at once, without an answer to report.
     */
    public static void upstreamFailed(OpsLog.Failure failure) {
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
    public static boolean upstreamFailurePending() {
        Frame frame = FRAME.get();
        return frame != null && !frame.upstream.isEmpty();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String id = UUID.randomUUID().toString();
        long started = System.nanoTime();
        MDC.put(KEY, id);
        response.setHeader(HEADER, id);
        var watched = new RequestStatusReason(response);
        var frame = new Frame(OpsLog.method(request), OpsLog.path(request));
        FRAME.set(frame);
        RequestStatusReason.Reason reason = null;
        try {
            chain.doFilter(request, watched);
            reason = watched.reason();
        } catch (IOException | ServletException | RuntimeException failure) {
            reason = failed(request, response, id, failure, frame);
        } finally {
            summary(frame, response.getStatus(), OpsLog.since(started), reason, watched.reference(), id);
            FRAME.remove();
            MDC.remove(KEY);
        }
    }

    private static RequestStatusReason.Reason failed(HttpServletRequest request, HttpServletResponse response, String id, Exception failure, Frame frame)
            throws IOException {
        if (response.isCommitted()) {
            // The answer was already on its way; usually the browser left. Nothing can be sent, so no ERROR.
            OpsLog.REQUEST.warn("Request ended early: {} {} {}", OpsLog.method(request), OpsLog.path(request), OpsLog.types(failure));
            return response.getStatus() >= 400 ? new RequestStatusReason.Reason("HTTP_" + response.getStatus(), RequestStatusReason.describe(response.getStatus())) : null;
        }
        frame.unexpected = failure;
        response.reset();
        response.setHeader(HEADER, id);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(500);
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":\"UNEXPECTED_ERROR\",\"message\":\"Something went wrong. Quote reference "
                + id + " when you report it.\",\"reference\":\"" + id + "\"}");
        return new RequestStatusReason.Reason("UNEXPECTED_ERROR", OpsLog.types(failure) + " at " + OpsLog.where(failure));
    }

    /**
     * Successes: "GET /x -> 200 in 3 ms". Failures add the code and why: "POST /x -> 403 DELETE_FORBIDDEN: Only the owner… in
     * 9 ms". A request with an upstream or unexpected failure writes ERROR lines instead ({@link #error}).
     */
    private static void summary(Frame frame, int status, long millis, RequestStatusReason.Reason reason, String answerReference, String id) {
        if (frame.unexpected == null && frame.upstream.isEmpty()) {
            if (quiet(frame.path, status)) return;
            var line = (status >= 500 || status == 403 || status == 429 ? OpsLog.HTTP.atWarn() : OpsLog.HTTP.atInfo())
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
            var line = OpsLog.REQUEST.atError().addKeyValue("exception.types", OpsLog.types(frame.unexpected));
            error(line, frame, status, millis, reason, "unexpected " + OpsLog.types(frame.unexpected) + " in " + OpsLog.where(frame.unexpected) + ": "
                    + OpsLog.safe(OpsLog.message(frame.unexpected)), frame.unexpected, id, null);
        }
    }

    /**
     * One ERROR line: "POST /x failed after 41 ms: {what failed}; answered 503 SERVICE_UNAVAILABLE; reference …; {hint}".
     * When the request still answered below 500 the line says so instead: "GET /x -> 200 in 50 ms, but {what failed}; the
     * request was answered without it".
     */
    private static void error(LoggingEventBuilder line, Frame frame, int status, long millis, RequestStatusReason.Reason reason, String what,
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
}
