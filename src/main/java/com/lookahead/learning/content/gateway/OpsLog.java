package com.lookahead.learning.content.gateway;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.core.env.Environment;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;

/**
 * DLV-969 (owner, 2026-11-04): the Gateway's operational log lines, in three loggers CloudWatch can filter on.
 * {@code lookahead.event}: the actions that matter (sign-in, sign-up, DEV gate, test sessions, rejected requests).
 * {@code lookahead.limit}: every throttle or rate-limit hit. {@code lookahead.upstream}: every outbound call.
 * Each line is a plain sentence plus queryable keys ({@code event.action}, {@code event.outcome}, {@code reason},
 * {@code upstream.service}, {@code upstream.operation}, {@code upstream.status}, {@code durationMs}, ...).
 *
 * <p>Never names, emails, passwords, tokens, codes, cookies, session ids, bodies, query strings or exception messages:
 * stable reason codes and exception types only. Successes are INFO; refusals, limit hits and upstream failures WARN.
 * Never ERROR: that level is kept for crashes, and the deploy fails on it.
 */
final class OpsLog {
    static final Logger EVENTS = LoggerFactory.getLogger("lookahead.event");
    static final Logger LIMITS = LoggerFactory.getLogger("lookahead.limit");
    static final Logger UPSTREAM = LoggerFactory.getLogger("lookahead.upstream");
    /** Domain's stable codes are upper case: {@code ACCOUNT_ADMISSION_REQUIRED}. Anything else is not copied. */
    private static final Pattern CODE = Pattern.compile("\"code\"\\s*:\\s*\"([A-Z][A-Z0-9_]{1,63})\"");

    private OpsLog() {}

    /** An important action that worked: INFO. */
    static LoggingEventBuilder success(String action) { return event(Level.INFO, action, "success"); }

    /** Refused on purpose (a rule, a limit, Domain's or Cognito's decision): WARN, with its stable reason code. */
    static LoggingEventBuilder refused(String action, String reason) {
        return event(Level.WARN, action, "refused").addKeyValue("reason", reason);
    }

    /** Could not be done because something it depends on failed: WARN, with its stable reason code. */
    static LoggingEventBuilder failed(String action, String reason) {
        return event(Level.WARN, action, "failure").addKeyValue("reason", reason);
    }

    static LoggingEventBuilder event(Level level, String action, String outcome) {
        return EVENTS.atLevel(level).addKeyValue("event.action", action).addKeyValue("event.outcome", outcome);
    }

    /** A throttle or rate limit refused {@code action}: WARN on {@code lookahead.limit}. {@code max} 0 when the limit is not ours to know. */
    static void limit(String name, int max, Duration window, String action, String message, Object... arguments) {
        var line = LIMITS.atWarn().addKeyValue("limit.name", name).addKeyValue("event.action", action)
                .addKeyValue("event.outcome", "refused").addKeyValue("reason", "TOO_MANY_REQUESTS");
        if (max > 0) line = line.addKeyValue("limit.max", max);
        if (window != null) line = line.addKeyValue("limit.window", window.toString());
        line.log(message, arguments);
    }

    /** The stable upper-case {@code code} of a JSON answer (Domain's refusal codes), or null. Nothing else of the body. */
    static String code(byte[] body) {
        if (body == null) return null;
        var found = CODE.matcher(new String(body, 0, Math.min(body.length, 4096), StandardCharsets.UTF_8));
        return found.find() ? found.group(1) : null;
    }

    static long since(long started) { return (System.nanoTime() - started) / 1_000_000; }

    /** The path only: never the query, at most 200 characters, and no line breaks to forge a second line. */
    static String path(URI uri) {
        String path = uri.getRawPath() == null ? "" : uri.getRawPath().replaceAll("[\\r\\n\\t]", "_");
        return path.length() > 200 ? path.substring(0, 200) + "…" : path;
    }

    // ----- outbound HTTP (the one gatewayHttp RestClient) -----

    /**
     * Which of our services a URI names: the configured Domain, Web, Identity and author-preview origins (exact host and
     * port), Cognito's public hosts, or {@code other}.
     */
    static Function<URI, String> services(Map<String, String> origins) {
        var known = new LinkedHashMap<String, URI>();
        origins.forEach((service, origin) -> {
            if (origin != null && !origin.isBlank()) known.put(service, URI.create(origin));
        });
        return uri -> {
            for (var entry : known.entrySet()) if (sameOrigin(entry.getValue(), uri)) return entry.getKey();
            return cognito(uri.getHost()) ? "cognito" : "other";
        };
    }

    /** The configured upstreams: {@code LOOKAHEAD_DOMAIN_UPSTREAM}, {@code LOOKAHEAD_WEB_UPSTREAM}, the local Identity and author previews. */
    static Function<URI, String> services(Environment environment) {
        var origins = new LinkedHashMap<String, String>();
        origins.put("domain", environment.getProperty("app.oauth.domain-api-upstream"));
        origins.put("web", environment.getProperty("app.gateway.web-upstream"));
        origins.put("identity", environment.getProperty("app.oauth.identity-upstream"));
        origins.put("author-previews", environment.getProperty("app.author-previews.upstream"));
        return services(origins);
    }

    static boolean cognito(String host) {
        if (host == null) return false;
        String name = host.toLowerCase(Locale.ROOT);
        return name.endsWith(".amazoncognito.com") || name.startsWith("cognito-idp.") && name.endsWith(".amazonaws.com");
    }

    private static boolean sameOrigin(URI configured, URI target) {
        return configured.getHost() != null && configured.getHost().equalsIgnoreCase(target.getHost())
                && port(configured) == port(target);
    }

    private static int port(URI uri) {
        if (uri.getPort() >= 0) return uri.getPort();
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    /**
     * One {@code lookahead.upstream} line per outbound call: service, method, path (no query), status and time to the
     * answer. A successful Web call (a static file) is DEBUG, other answers INFO, 5xx and no answer at all WARN. Headers
     * and bodies are never read.
     */
    static ClientHttpRequestInterceptor upstream(Function<URI, String> services) {
        return (request, body, execution) -> {
            URI uri = request.getURI();
            String service = services.apply(uri), method = request.getMethod().name(), path = path(uri);
            long started = System.nanoTime();
            ClientHttpResponse response;
            try {
                response = execution.execute(request, body);
            } catch (IOException failure) {
                long millis = since(started);
                String reason = failure instanceof java.net.http.HttpTimeoutException || failure instanceof java.net.SocketTimeoutException
                        ? "TIMEOUT" : "NO_RESPONSE";
                call(UPSTREAM.atWarn(), service, method + " " + path, millis).addKeyValue("event.outcome", "failure")
                        .addKeyValue("reason", reason)
                        .log("Upstream {} {} {} failed after {} ms with no answer ({}): {}", service, method, path, millis, reason,
                                RequestLog.types(failure));
                throw failure;
            }
            int status = response.getStatusCode().value();
            long millis = since(started);
            var level = status >= 500 ? UPSTREAM.atWarn() : status < 400 && "web".equals(service) ? UPSTREAM.atDebug() : UPSTREAM.atInfo();
            call(level, service, method + " " + path, millis).addKeyValue("upstream.status", status)
                    .addKeyValue("event.outcome", status < 400 ? "success" : "failure")
                    .log("Upstream {} {} {} -> {} in {} ms", service, method, path, status, millis);
            return response;
        };
    }

    private static LoggingEventBuilder call(LoggingEventBuilder line, String service, String operation, long millis) {
        return line.addKeyValue("upstream.service", service).addKeyValue("upstream.operation", operation).addKeyValue("durationMs", millis);
    }

    // ----- AWS SDK calls -----

    /** One {@code lookahead.upstream} line for an AWS SDK call: INFO on success. */
    static <T> T aws(String service, String operation, Supplier<T> call) { return aws(service, operation, false, call); }

    /**
     * One {@code lookahead.upstream} line for an AWS SDK call ({@code quiet}: success at DEBUG, for polled reads). A service
     * answer logs its error code and HTTP status (INFO for 4xx, WARN for 5xx); no answer at all logs the exception types at
     * WARN. Messages are never logged: Cognito's can name the account. The exception is rethrown unchanged.
     */
    static <T> T aws(String service, String operation, boolean quiet, Supplier<T> call) {
        long started = System.nanoTime();
        try {
            T result = call.get();
            long millis = since(started);
            call(quiet ? UPSTREAM.atDebug() : UPSTREAM.atInfo(), service, operation, millis).addKeyValue("event.outcome", "success")
                    .log("Upstream {} {} succeeded in {} ms", service, operation, millis);
            return result;
        } catch (AwsServiceException answered) {
            long millis = since(started);
            int status = answered.statusCode();
            String code = awsCode(answered);
            call(status >= 500 ? UPSTREAM.atWarn() : UPSTREAM.atInfo(), service, operation, millis).addKeyValue("event.outcome", "failure")
                    .addKeyValue("upstream.status", status).addKeyValue("upstream.code", code)
                    .log("Upstream {} {} -> {} {} in {} ms", service, operation, status, code, millis);
            throw answered;
        } catch (RuntimeException failure) {
            long millis = since(started);
            call(UPSTREAM.atWarn(), service, operation, millis).addKeyValue("event.outcome", "failure").addKeyValue("reason", "NO_RESPONSE")
                    .log("Upstream {} {} failed after {} ms with no answer: {}", service, operation, millis, RequestLog.types(failure));
            throw failure;
        }
    }

    /** The AWS error code ({@code NotAuthorizedException}, {@code ThrottlingException}), else the exception's type. */
    static String awsCode(AwsServiceException answered) {
        var details = answered.awsErrorDetails();
        String code = details == null ? null : details.errorCode();
        return code != null && code.matches("[A-Za-z0-9_.:-]{1,80}") ? code : answered.getClass().getSimpleName();
    }

    /**
     * Logs every retry the AWS SDK makes by itself: "attempt 2 of 3", and what the attempt before got. Added to an SDK
     * client that retries; the final outcome is the {@link #aws} line around the call.
     */
    static final class SdkRetries implements ExecutionInterceptor {
        static final ExecutionAttribute<Integer> ATTEMPT = new ExecutionAttribute<>("lookahead.retry.attempt");
        static final ExecutionAttribute<Integer> LAST_STATUS = new ExecutionAttribute<>("lookahead.retry.lastStatus");
        private final String service;
        private final int maxAttempts;

        SdkRetries(String service, int maxAttempts) { this.service = service; this.maxAttempts = maxAttempts; }

        @Override public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes attributes) {
            Integer previous = attributes.getAttribute(ATTEMPT);
            int attempt = previous == null ? 1 : previous + 1;
            attributes.putAttribute(ATTEMPT, attempt);
            if (attempt > 1) {
                Integer status = attributes.getAttribute(LAST_STATUS);
                String operation = attributes.getAttribute(SdkExecutionAttribute.OPERATION_NAME);
                String before = status == null || status == 0 ? "no answer" : "HTTP " + status;
                UPSTREAM.atWarn().addKeyValue("upstream.service", service).addKeyValue("upstream.operation", operation)
                        .addKeyValue("retry.attempt", attempt).addKeyValue("retry.max", maxAttempts)
                        .log("Upstream {} {} attempt {} of {}: retrying after {}", service, operation, attempt, maxAttempts, before);
            }
            attributes.putAttribute(LAST_STATUS, 0);
        }

        @Override public void afterTransmission(Context.AfterTransmission context, ExecutionAttributes attributes) {
            attributes.putAttribute(LAST_STATUS, context.httpResponse().statusCode());
        }
    }
}
