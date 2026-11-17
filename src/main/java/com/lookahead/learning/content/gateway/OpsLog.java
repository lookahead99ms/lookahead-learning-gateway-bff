package com.lookahead.learning.content.gateway;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
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
 * DLV-969 (owner, 2026-11-04): the Gateway's operational log lines, in three loggers.
 * {@code lookahead.event}: the actions that matter (sign-in, sign-up, DEV gate, test sessions, rejected requests).
 * {@code lookahead.limit}: every throttle or rate-limit hit. {@code lookahead.upstream}: every outbound call.
 * Each line is a plain sentence; the keys ({@code event.action}, {@code event.outcome}, {@code reason},
 * {@code upstream.service}, {@code upstream.operation}, {@code upstream.status}, {@code durationMs}, ...) stay on the
 * event for tests and for a log pipeline if one is ever wanted, but the plain console pattern does not render them, so
 * every sentence says its own reason code.
 *
 * <p>Plain logs (owner decision 2026-11-17). Levels: INFO is normal progress; WARN is an expected refusal (wrong
 * password, limit hit, waiting account, a 4xx answer from an upstream); ERROR is something an operator must act on: an
 * upstream that gave no answer, answered 5xx, or an AWS call refused for permissions or a missing resource. An ERROR
 * line is written once per failure, at the end of the request by {@link RequestLog}, so it can say what the browser got
 * ({@link Failure}). On ERROR lines the dependency's own exception message is quoted, after {@link #safe} masks the
 * shapes a secret could take; WARN and INFO lines never quote a message, only exception types and stable codes. Never
 * names, emails, passwords, tokens, codes, cookies, session ids, bodies or query strings.
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

    /**
     * A throttle or rate limit refused {@code action}: WARN on {@code lookahead.limit}. {@code max} 0 when the limit is not
     * ours to know. The caller's {@code message} names the limit ({@code name}) itself: the keys are not on the plain line.
     */
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

    /**
     * For a line on a hot path (a polled route, every request): due when the key changes, then at most once per
     * {@code every} while it stays the same. {@link #clear} after recovery so the next failure logs at once.
     */
    static final class Repeats {
        private final long everyNanos;
        private final java.util.function.LongSupplier clock;
        private String last;
        private long at;
        Repeats(Duration every) { this(every, System::nanoTime); }
        Repeats(Duration every, java.util.function.LongSupplier clock) { this.everyNanos = every.toNanos(); this.clock = clock; }
        synchronized boolean due(String key) {
            long now = clock.getAsLong();
            if (key.equals(last) && now - at < everyNanos) return false;
            last = key; at = now;
            return true;
        }
        synchronized void clear() { last = null; }
    }

    /** The path only: never the query, at most 200 characters, and no line breaks to forge a second line. */
    static String path(URI uri) {
        String path = uri.getRawPath() == null ? "" : uri.getRawPath().replaceAll("[\\r\\n\\t]", "_");
        return path.length() > 200 ? path.substring(0, 200) + "…" : path;
    }

    /** {@code host[:port]} of a URI: never its user, path or query. */
    static String host(URI uri) {
        if (uri.getHost() == null) return "unknown host";
        return uri.getPort() >= 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
    }

    // ----- quoting a dependency's message on ERROR lines -----

    private static final Pattern EMAIL = Pattern.compile("[^\\s@\"'<>]+@[^\\s@\"'<>]+\\.[A-Za-z]{2,}");
    private static final Pattern CREDENTIAL_SCHEME = Pattern.compile("(?i)\\b(Bearer|Basic|Digest)\\s+[A-Za-z0-9._~+/=-]{4,}");
    private static final Pattern SECRET_HEADER = Pattern.compile("(?i)\\b(Authorization|Proxy-Authorization|Cookie|Set-Cookie|X-LookAhead-Gateway-Secret|X-LookAhead-SignIn-Proof|X-LookAhead-Challenge)\\s*[:=]\\s*[^;,]+");
    private static final Pattern SECRET_VALUE = Pattern.compile("(?i)\\b([A-Za-z_.-]*(?:password|passwd|secret|token|session|cookie|credential|code)s?)\\s*[=:]\\s*[^\\s;,&\"']+");
    private static final Pattern QUERY = Pattern.compile("\\?[^\\s\"'<>)]*");
    static final int MESSAGE_LIMIT = 400;

    /**
     * A dependency's message as one ERROR line may quote it: one line, at most {@value #MESSAGE_LIMIT} characters, with
     * email addresses, query strings, {@code Bearer}/{@code Basic} credentials, credential headers and
     * {@code password=}/{@code token=}-shaped values masked. Null or blank becomes "no message".
     */
    static String safe(String message) {
        if (message == null || message.isBlank()) return "no message";
        String text = message.replaceAll("[\\r\\n\\t]+", " ").replaceAll(" {2,}", " ").strip();
        text = QUERY.matcher(text).replaceAll("?[query hidden]");
        text = CREDENTIAL_SCHEME.matcher(text).replaceAll("$1 [hidden]");
        text = SECRET_HEADER.matcher(text).replaceAll("$1=[hidden]");
        text = SECRET_VALUE.matcher(text).replaceAll("$1=[hidden]");
        text = EMAIL.matcher(text).replaceAll("[email]");
        return text.length() > MESSAGE_LIMIT ? text.substring(0, MESSAGE_LIMIT) + "…" : text;
    }

    /**
     * "{@code SocketTimeoutException: Read timed out}": the exception types (outermost first, as {@link RequestLog#types})
     * and the innermost message that says anything, {@link #safe}. Spring's and the SDK's wrappers repeat the URL and
     * the status in their own messages, so the deepest cause is the one quoted.
     */
    static String quote(Throwable failure) {
        String message = null;
        for (Throwable at = failure; at != null; at = at.getCause()) if (at.getMessage() != null && !at.getMessage().isBlank()) message = at.getMessage();
        return RequestLog.types(failure) + ": " + safe(message);
    }

    /** What the Gateway knows about a failure's cause, from the exception alone; null when nothing more can be said. */
    static String hint(String service, Throwable failure) {
        boolean aws = "cognito".equals(service) || "dynamodb".equals(service);
        String text = "";
        for (Throwable at = failure; at != null; at = at.getCause()) {
            text += " " + at.getClass().getSimpleName() + " " + (at.getMessage() == null ? "" : at.getMessage().toLowerCase(Locale.ROOT));
        }
        if (text.contains("UnknownHostException") || text.contains("name or service not known") || text.contains("nodename nor servname"))
            return "the host name did not resolve: check the configured upstream and its DNS (Cloud Map) entry";
        if (text.contains("SSLHandshakeException") || text.contains("SSLException") || text.contains("certificate") || text.contains("pkix"))
            return "the TLS handshake failed: check the serving certificate and the internal mTLS bundle on both sides";
        if (text.contains("unable to load credentials") || text.contains("CredentialsException"))
            return "the task role credentials could not be loaded: check the ECS task role and the container credentials endpoint";
        if (text.contains("HttpConnectTimeoutException") || text.contains("ConnectException") || text.contains("connect timed out")
                || text.contains("connection refused") || text.contains("connection reset"))
            return aws ? "a connect failure to an AWS endpoint from the task's subnet usually means the VPC endpoint or its security group does not let the Gateway through"
                    : "nothing accepted the connection: check that the " + service + " task is running, its Cloud Map name points at a live task and its security group allows the Gateway";
        if (text.contains("timed out") || text.contains("HttpTimeoutException") || text.contains("ApiCallTimeoutException") || text.contains("ApiCallAttemptTimeoutException"))
            return "the connection was made but no answer came in time: the " + service + " is up but slow or stuck";
        return null;
    }

    /** What the Gateway knows about an AWS answer with this status and code; null when nothing more can be said. */
    static String awsHint(int status, String code) {
        if (status == 403 || "AccessDeniedException".equals(code) || "UnrecognizedClientException".equals(code) || "InvalidSignatureException".equals(code))
            return "the task role lacks this permission or its credentials are wrong: check the app-task role's policy";
        if ("ResourceNotFoundException".equals(code)) return "the configured table or user pool does not exist in this region: check the setting";
        if (status >= 500) return "AWS answered a server error; the SDK already retried where its retry mode allows";
        return null;
    }

    /**
     * One upstream failure an operator must act on, logged at ERROR once the request's answer is known
     * ({@link RequestLog#upstreamFailed}). {@code target} is the {@code host[:port]} for HTTP (rendered "at host") or the
     * named resource for AWS, "table x" / "pool x" / "app client x" (rendered "on table x"); {@code status}
     * and {@code code} are the upstream's answer (null for no answer); {@code cause} is the exception (its stack trace
     * follows the line) or null for a 5xx answer; {@code reason} is the stable code for the {@code reason} key. A
     * {@code millis} below zero means the time is not known (a failure caught after the call, not around it).
     */
    record Failure(String service, String operation, String target, long millis, Integer status, String code, Throwable cause, String reason) {
        /** "upstream domain GET /x at host:8443 gave no answer in 3002 ms (SocketTimeoutException: Read timed out)". */
        String words() {
            String where = target == null ? "" : " " + (target.contains(" ") ? "on" : "at") + " " + target;
            String what = "upstream".equals(service) ? "the upstream call for " + operation : "upstream " + service + " " + operation + where;
            if (status == null && millis < 0) return what + " failed (" + quote(cause) + ")";
            if (status == null) return what + " gave no answer in " + millis + " ms" + (cause == null ? "" : " (" + quote(cause) + ")");
            if (cause instanceof AwsServiceException answered) {
                var details = answered.awsErrorDetails();
                String message = details == null || details.errorMessage() == null ? answered.getMessage() : details.errorMessage();
                String requestId = answered.requestId() == null ? "" : "; AWS request id " + safe(answered.requestId());
                return what + (status == 403 || status == 400 ? " was refused" : " failed") + " with HTTP " + status + " (" + code + ": " + safe(message) + requestId + ")";
            }
            return what + " answered " + status + (code == null ? "" : " " + code) + " in " + millis + " ms";
        }

        /** What the code knows about the cause, for the end of the ERROR line; null when nothing more can be said. */
        String hint() {
            if (status == null) return cause == null ? null : OpsLog.hint(service, cause);
            if (cause instanceof AwsServiceException) return awsHint(status, code);
            if (cause != null) return OpsLog.hint(service, cause);
            return status >= 500 ? "the " + service + " answered a server error; its own log has the detail" : null;
        }

        LoggingEventBuilder keys(LoggingEventBuilder line) {
            line = line.addKeyValue("upstream.service", service).addKeyValue("upstream.operation", operation).addKeyValue("durationMs", millis)
                    .addKeyValue("event.outcome", "failure").addKeyValue("reason", reason);
            if (status != null) line = line.addKeyValue("upstream.status", status);
            if (code != null) line = line.addKeyValue("upstream.code", code);
            if (cause != null) line = line.addKeyValue("exception.types", RequestLog.types(cause));
            return line;
        }
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
     * answer. A successful Web call (a static file) is DEBUG, other answers up to 4xx INFO. A 5xx answer or no answer at
     * all is an ERROR, written once the request's own answer is known ({@link Failure}). Headers and bodies are never read.
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
                RequestLog.upstreamFailed(new Failure(service, method + " " + path, host(uri), millis, null, null, failure, reason));
                throw failure;
            }
            int status = response.getStatusCode().value();
            long millis = since(started);
            if (status >= 500) {
                RequestLog.upstreamFailed(new Failure(service, method + " " + path, host(uri), millis, status, null, null, "HTTP_" + status));
                return response;
            }
            var level = status < 400 && "web".equals(service) ? UPSTREAM.atDebug() : UPSTREAM.atInfo();
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
    static <T> T aws(String service, String operation, Supplier<T> call) { return aws(service, operation, null, false, call); }

    /** As {@link #aws(String, String, String, boolean, Supplier)} without a resource name. */
    static <T> T aws(String service, String operation, boolean quiet, Supplier<T> call) { return aws(service, operation, null, quiet, call); }

    /** AWS error codes that are a limit, not something to act on, whatever their status. */
    private static final Set<String> LIMIT_CODES = Set.of("TooManyRequestsException", "ThrottlingException", "LimitExceededException",
            "ProvisionedThroughputExceededException", "RequestLimitExceeded");
    /** AWS error codes for a misconfiguration, whatever their status. */
    private static final Set<String> ACT_CODES = Set.of("AccessDeniedException", "UnrecognizedClientException", "InvalidSignatureException",
            "ResourceNotFoundException", "ExpiredTokenException", "IncompleteSignature", "InvalidClientTokenId");

    /**
     * One {@code lookahead.upstream} line for an AWS SDK call ({@code quiet}: success at DEBUG, for polled reads;
     * {@code resource}: the table or pool, for the ERROR line). An expected refusal (a 4xx such as
     * {@code NotAuthorizedException}, or a throttle) is INFO and never quotes the message, which can name the account. A
     * 5xx, a 403, a permission or missing-resource code, or no answer at all is an ERROR with the message quoted, written
     * once the request's answer is known ({@link Failure}). The exception is rethrown unchanged.
     */
    static <T> T aws(String service, String operation, String resource, boolean quiet, Supplier<T> call) {
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
            if (!LIMIT_CODES.contains(code) && status != 429 && (status >= 500 || status == 403 || ACT_CODES.contains(code)))
                RequestLog.upstreamFailed(new Failure(service, operation, resource, millis, status, code, answered, code));
            else call(UPSTREAM.atInfo(), service, operation, millis).addKeyValue("event.outcome", "failure")
                    .addKeyValue("upstream.status", status).addKeyValue("upstream.code", code)
                    .log("Upstream {} {} -> {} {} in {} ms", service, operation, status, code, millis);
            throw answered;
        } catch (RuntimeException failure) {
            long millis = since(started);
            RequestLog.upstreamFailed(new Failure(service, operation, resource, millis, null, null, failure, "NO_RESPONSE"));
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
     * client that retries. A retry is WARN, not ERROR: it is not final; the {@link #aws} line around the call carries the
     * outcome, and the ERROR line when the last attempt fails too.
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
