package com.lookahead.learning.content.gateway;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * DLV-969 (owner, 2026-11-04): every browser request gets one request ID. It is on every log line written while the
 * request runs, goes to Domain and Web as {@code X-Request-Id}, and comes back to the browser, so one search in
 * CloudWatch shows the whole request. Each request also writes one summary line: method, path (never the query),
 * status and time taken, and for every 4xx and 5xx its code and the reason in words ({@link StatusReason}). 403, 429 and
 * 5xx are WARN. Health checks and successful static files stay quiet.
 * <p>A failure that escapes everything else is logged at ERROR with its stack trace and the request ID as its
 * reference; the caller gets that reference and nothing else.
 */
@Component @Order(Ordered.HIGHEST_PRECEDENCE)
public final class RequestLog extends OncePerRequestFilter {
    static final String HEADER = "X-Request-Id";
    static final String KEY = "requestId";
    private static final Logger requests = LoggerFactory.getLogger("lookahead.http");
    private static final Logger failures = LoggerFactory.getLogger(RequestLog.class);
    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");

    /** The request ID of the request this thread is serving, or a new one outside a request. */
    static String reference() {
        String id = MDC.get(KEY);
        return id != null ? id : UUID.randomUUID().toString();
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
        StatusReason.Reason reason = null;
        try {
            chain.doFilter(request, watched);
            reason = watched.reason();
        } catch (IOException | ServletException | RuntimeException failure) {
            reason = failed(request, response, id, failure);
        } finally {
            summary(request, response.getStatus(), (System.nanoTime() - started) / 1_000_000, reason);
            MDC.remove(KEY);
        }
    }

    private static StatusReason.Reason failed(HttpServletRequest request, HttpServletResponse response, String id, Exception failure)
            throws IOException {
        if (response.isCommitted()) {
            // The answer was already on its way; usually the browser left. Nothing can be sent, so no ERROR.
            failures.warn("Request ended early: {} {} {}", method(request), path(request), types(failure));
            return response.getStatus() >= 400 ? new StatusReason.Reason("HTTP_" + response.getStatus(), StatusReason.describe(response.getStatus())) : null;
        }
        failures.error("Unexpected failure reference={} {} {}", id, method(request), path(request), failure);
        response.reset();
        response.setHeader(HEADER, id);
        response.setHeader("Cache-Control", "no-store");
        response.setStatus(500);
        response.setContentType("application/json");
        response.getWriter().write("{\"code\":\"UNEXPECTED_ERROR\",\"message\":\"Something went wrong. Quote reference "
                + id + " when you report it.\",\"reference\":\"" + id + "\"}");
        return new StatusReason.Reason("UNEXPECTED_ERROR", types(failure) + ": see the ERROR line with the same requestId");
    }

    /** Successes: "GET /x -> 200 in 3 ms". Failures add the code and why: "POST /x -> 403 DELETE_FORBIDDEN: Only the owner… in 9 ms". */
    private static void summary(HttpServletRequest request, int status, long millis, StatusReason.Reason reason) {
        String path = path(request);
        if (quiet(path, status)) return;
        var line = (status >= 500 || status == 403 || status == 429 ? requests.atWarn() : requests.atInfo())
                .addKeyValue("http.method", method(request)).addKeyValue("url.path", path)
                .addKeyValue("http.status", status).addKeyValue("durationMs", millis);
        if (reason == null) {
            line.log("{} {} -> {} in {} ms", method(request), path, status, millis);
            return;
        }
        line.addKeyValue("error.code", reason.code()).addKeyValue("error.reason", reason.words())
                .log("{} {} -> {} {}: {} in {} ms", method(request), path, status, reason.code(), reason.words(), millis);
    }

    static boolean quiet(String path, int status) {
        if (path.startsWith("/actuator/") || path.equals("/health")) return true;
        String last = path.substring(path.lastIndexOf('/') + 1);
        return status < 400 && last.contains(".");
    }

    /** The exception and its causes by type only, e.g. "ResourceAccessException < ConnectException": messages can hold secrets. */
    static String types(Throwable failure) {
        var names = new java.util.ArrayList<String>();
        for (Throwable at = failure; at != null && names.size() < 5; at = at.getCause()) names.add(at.getClass().getSimpleName());
        return String.join(" < ", names);
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
