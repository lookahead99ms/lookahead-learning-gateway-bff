package com.lookahead.gateway.log;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;
import org.slf4j.spi.LoggingEventBuilder;
import org.springframework.core.env.Environment;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.oauth2.core.OAuth2Error;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttribute;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.core.interceptor.SdkExecutionAttribute;

/**
 * DLV-969 (owner, 2026-11-04): the Gateway BFF's operational log lines, in three loggers (and {@code lookahead.lifecycle}
 * for a refused start, DLV-1015). Every logger of the application is declared here, also the two {@link RequestLog}
 * writes on ({@code lookahead.http} and the one named for that class).
 * {@code lookahead.event}: the actions that matter (sign-in, sign-up, DEV gate, test sessions, rejected requests).
 * {@code lookahead.limit}: every throttle or rate-limit hit. {@code lookahead.upstream}: every outbound call.
 * {@code lookahead.security.audit}: the DEV security audit codes ({@link #audit}), in their own fixed format.
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
 *
 * <p>Exception, decided 2026-11-25 (DLV-1015): this class holds several jobs and is large (rule 5: one responsibility
 * per class): the event, limit, refused-start and security-audit lines, the masking of a quoted message, the failure
 * record behind an ERROR line, and the lines around outbound HTTP and AWS SDK calls (the two interceptors and
 * {@code aws}). It is the one shared class for the shape of log lines (rule 6); split out, the interceptors and the AWS
 * wrapper would each be a class that exists only to log, so it stays one class.
 */
public final class OpsLog {
    static final Logger EVENTS = LoggerFactory.getLogger("lookahead.event");
    static final Logger LIMITS = LoggerFactory.getLogger("lookahead.limit");
    static final Logger UPSTREAM = LoggerFactory.getLogger("lookahead.upstream");
    /** Start, stop, health and a refused start ({@link #startupRefused}); {@link LifecycleLog} and {@link HealthLog} write on it too ({@link #lifecycle}). */
    static final Logger LIFECYCLE = LoggerFactory.getLogger("lookahead.lifecycle");
    /** The one summary line of each browser request, written by {@link RequestLog}. */
    static final Logger HTTP = LoggerFactory.getLogger("lookahead.http");
    /** {@link RequestLog}'s own two failure lines (a request that ended early, an unexpected failure): named for that class, as they always were. */
    static final Logger REQUEST = LoggerFactory.getLogger(RequestLog.class);
    /** Domain's stable codes are upper case: {@code ACCOUNT_ADMISSION_REQUIRED}. Anything else is not copied. */
    private static final Pattern CODE = Pattern.compile("\"code\"\\s*:\\s*\"([A-Z][A-Z0-9_]{1,63})\"");

    private OpsLog() {}

    /** An important action that worked: INFO. */
    public static LoggingEventBuilder success(String action) { return event(Level.INFO, action, "success"); }

    /** Refused on purpose (a rule, a limit, Domain's or Cognito's decision): WARN, with its stable reason code. */
    public static LoggingEventBuilder refused(String action, String reason) {
        return event(Level.WARN, action, "refused").addKeyValue("reason", reason);
    }

    /** Could not be done because something it depends on failed: WARN, with its stable reason code. */
    public static LoggingEventBuilder failed(String action, String reason) {
        return event(Level.WARN, action, "failure").addKeyValue("reason", reason);
    }

    public static LoggingEventBuilder event(Level level, String action, String outcome) {
        return EVENTS.atLevel(level).addKeyValue("event.action", action).addKeyValue("event.outcome", outcome);
    }

    /** A line about the application's own life (start, availability, health, stop, a refused start) on {@code lookahead.lifecycle}; {@code event.action} is its first key. */
    static LoggingEventBuilder lifecycle(Level level, String action) {
        return LIFECYCLE.atLevel(level).addKeyValue("event.action", action);
    }

    /**
     * A throttle or rate limit refused {@code action}: WARN on {@code lookahead.limit}. {@code max} 0 when the limit is not
     * ours to know. The caller's {@code message} names the limit ({@code name}) itself: the keys are not on the plain line.
     */
    public static void limit(String name, int max, Duration window, String action, String message, Object... arguments) {
        var line = LIMITS.atWarn().addKeyValue("limit.name", name).addKeyValue("event.action", action)
                .addKeyValue("event.outcome", "refused").addKeyValue("reason", "TOO_MANY_REQUESTS");
        if (max > 0) line = line.addKeyValue("limit.max", max);
        if (window != null) line = line.addKeyValue("limit.window", window.toString());
        line.log(message, arguments);
    }

    /**
     * DLV-969 (owner, 2026-11-04): a start the Gateway BFF refuses says which setting, secret or file was wrong, by NAME, before
     * Spring Boot's own "Application run failed" line. One WARN on {@code lookahead.lifecycle} with {@code event.action}
     * {@code startup.refused}, the {@code setting} (property and the variable that sets it) and a stable {@code reason}.
     * Never the value: settings hold secrets, certificates, keys and internal URLs.
     *
     * <p>Logs the refusal and returns the exception to throw. {@code message} is the caller's fixed text (never a value) and
     * stays the exception's message, so existing messages and their checks are unchanged.
     */
    public static IllegalStateException startupRefused(String setting, String reason, String message) {
        lifecycle(Level.WARN, "startup.refused").addKeyValue("event.outcome", "failure")
                .addKeyValue("setting", setting).addKeyValue("reason", reason)
                .log("Startup refused: {} {} ({}): {}; the Gateway will not start", setting, words(reason), reason, message);
        return new IllegalStateException(message);
    }

    /** The reason in words for the common codes; any other code is already descriptive. */
    static String words(String reason) {
        return switch (reason) {
            case "MISSING" -> "is missing or empty";
            case "INVALID" -> "is set but not valid";
            case "NOT_ALLOWED" -> "is not allowed in this deployment";
            default -> "was rejected";
        };
    }

    /**
     * One WARN line for a request this application refused or could not complete itself, taken from the answer it is about
     * to give: the answer's own {@code code} (or {@code HTTP_<status>}) and why; a 5xx answer is a failure, anything else a
     * refusal. {@code sentence} is the caller's fixed text with three places: the event, the code and why. Never the body.
     * Returns the answer, so the caller can refuse in one statement.
     */
    public static ResponseEntity<?> refusedAnswer(String sentence,String event,ResponseEntity<?> answer,String why){
        int status=answer.getStatusCode().value();
        String code=answer.getBody() instanceof Map<?,?> body&&body.get("code") instanceof String value?value:"HTTP_"+status;
        (status>=500?failed(event,code):refused(event,code)).addKeyValue("http.status",status)
            .log(sentence,event,code,why);
        return answer;
    }

    /**
     * One line for an upstream's answer that this application passes on as a refusal: the stable {@code code} of the
     * answer's body (or {@code HTTP_<status>}); a 5xx answer is a failure, anything else a refusal. {@code sentence} is the
     * caller's fixed text with three places: {@code subject} (what was asked for), the code and the status. Never the body.
     */
    public static void refusedByUpstream(String sentence,String event,String subject,byte[] body,int status){
        String code=code(body);code=code==null?"HTTP_"+status:code;
        (status>=500?failed(event,code):refused(event,code)).addKeyValue("upstream.status",status)
            .log(sentence,subject,code,status);
    }

    /**
     * The code of an OAuth error as a log line may carry it: the provider's code when it has the fixed lower-case shape
     * ({@code invalid_grant}, {@code access_denied}), else {@code otherwise}. Never the error's description.
     */
    public static String oauthCode(OAuth2Error error,String otherwise){
        return error != null && error.getErrorCode() != null && error.getErrorCode().matches("[a-z_]{1,64}") ? error.getErrorCode() : otherwise;
    }

    /** The stable upper-case {@code code} of a JSON answer (Domain's refusal codes), or null. Nothing else of the body. */
    public static String code(byte[] body) {
        if (body == null) return null;
        var found = CODE.matcher(new String(body, 0, Math.min(body.length, 4096), StandardCharsets.UTF_8));
        return found.find() ? found.group(1) : null;
    }

    static long since(long started) { return (System.nanoTime() - started) / 1_000_000; }

    /** The fixed event codes of the DEV security audit. */
    public enum AuditEvent { ADMISSION_GRANTED, ADMISSION_DENIED, AUTHENTICATION_REJECTED, AUTHORIZATION_REJECTED, SESSION_ENDED }

    /**
     * The DEV security audit line: INFO on {@code lookahead.security.audit}, a fixed event code and a random id only; no
     * request, identity, token, exception or payload fields.
     */
    public static void audit(AuditEvent event) {
        LoggerFactory.getLogger("lookahead.security.audit").info("LOOKAHEAD_SECURITY_V1 event={} id={}",event.name(),UUID.randomUUID());
    }

    /** The path only: never the query, at most 200 characters, and no line breaks to forge a second line. */
    static String path(URI uri) { return pathOnly(uri.getRawPath()); }

    private static String pathOnly(String raw) {
        String path = raw == null ? "" : raw.replaceAll("[\\r\\n\\t]", "_");
        return path.length() > 200 ? path.substring(0, 200) + "…" : path;
    }

    /** {@code host[:port]} of a URI: never its user, path or query. */
    static String host(URI uri) {
        if (uri.getHost() == null) return "unknown host";
        return uri.getPort() >= 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
    }

    private static final Set<String> METHODS = Set.of("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS");

    /** The exception and its causes by type only, e.g. "ResourceAccessException < ConnectException". */
    public static String types(Throwable failure) {
        var names = new ArrayList<String>();
        for (Throwable at = failure; at != null && names.size() < 5; at = at.getCause()) names.add(at.getClass().getSimpleName());
        return String.join(" < ", names);
    }

    /** The exception's own message, else the innermost cause's. */
    static String message(Throwable failure) {
        String message = failure.getMessage();
        for (Throwable at = failure.getCause(); at != null && (message == null || message.isBlank()); at = at.getCause()) message = at.getMessage();
        return message;
    }

    /** Where the failure was thrown: the first frame in our own code, "DomainProxy.forward (DomainProxy.java:48)", else the top frame. */
    static String where(Throwable failure) {
        StackTraceElement[] trace = failure.getStackTrace();
        if (trace == null || trace.length == 0) return "an unknown place";
        StackTraceElement frame = trace[0];
        for (StackTraceElement at : trace) if (at.getClassName().startsWith("com.lookahead.")) { frame = at; break; }
        String type = frame.getClassName().substring(frame.getClassName().lastIndexOf('.') + 1);
        return type + "." + frame.getMethodName() + " (" + frame.getFileName() + ":" + frame.getLineNumber() + ")";
    }

    public static String method(HttpServletRequest request) {
        return METHODS.contains(request.getMethod()) ? request.getMethod() : "OTHER";
    }

    /** The path only: never the query, at most 200 characters, and no line breaks to forge a second line. */
    public static String path(HttpServletRequest request) { return pathOnly(request.getRequestURI()); }

    // ----- quoting a dependency's message on ERROR lines -----

    /** The shape of an email address, masked wherever a line quotes text from outside ({@link #safe}, the request summary's reason). */
    static final Pattern EMAIL = Pattern.compile("[^\\s@\"'<>]+@[^\\s@\"'<>]+\\.[A-Za-z]{2,}");
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
     * "{@code SocketTimeoutException: Read timed out}": the exception types (outermost first, as {@link #types})
     * and the innermost message that says anything, {@link #safe}. Spring's and the SDK's wrappers repeat the URL and
     * the status in their own messages, so the deepest cause is the one quoted.
     */
    static String quote(Throwable failure) {
        String message = null;
        for (Throwable at = failure; at != null; at = at.getCause()) if (at.getMessage() != null && !at.getMessage().isBlank()) message = at.getMessage();
        return types(failure) + ": " + safe(message);
    }

    /** What the Gateway BFF knows about a failure's cause, from the exception alone; null when nothing more can be said. */
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

    /** What the Gateway BFF knows about an AWS answer with this status and code; null when nothing more can be said. */
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
    public record Failure(String service, String operation, String target, long millis, Integer status, String code, Throwable cause, String reason) {
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
            if (cause != null) line = line.addKeyValue("exception.types", types(cause));
            return line;
        }
    }

    // ----- outbound HTTP (the one upstreamHttp RestClient) -----

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
    public static Function<URI, String> services(Environment environment) {
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
    public static ClientHttpRequestInterceptor upstream(Function<URI, String> services) {
        return (request, body, execution) -> {
            URI uri = request.getURI();
            String service = services.apply(uri), method = request.getMethod().name(), path = path(uri);
            long started = System.nanoTime();
            ClientHttpResponse response;
            try {
                response = execution.execute(request, body);
            } catch (IOException failure) {
                long millis = since(started);
                String reason = failure instanceof HttpTimeoutException || failure instanceof SocketTimeoutException
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
    public static <T> T aws(String service, String operation, String resource, boolean quiet, Supplier<T> call) {
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
    public static String awsCode(AwsServiceException answered) {
        var details = answered.awsErrorDetails();
        String code = details == null ? null : details.errorCode();
        return code != null && code.matches("[A-Za-z0-9_.:-]{1,80}") ? code : answered.getClass().getSimpleName();
    }

    /**
     * Logs every retry the AWS SDK makes by itself: "attempt 2 of 3", and what the attempt before got. Added to an SDK
     * client that retries. A retry is WARN, not ERROR: it is not final; the {@link #aws} line around the call carries the
     * outcome, and the ERROR line when the last attempt fails too.
     */
    public static final class SdkRetries implements ExecutionInterceptor {
        static final ExecutionAttribute<Integer> ATTEMPT = new ExecutionAttribute<>("lookahead.retry.attempt");
        static final ExecutionAttribute<Integer> LAST_STATUS = new ExecutionAttribute<>("lookahead.retry.lastStatus");
        private final String service;
        private final int maxAttempts;

        public SdkRetries(String service, int maxAttempts) { this.service = service; this.maxAttempts = maxAttempts; }

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
