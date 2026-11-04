package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * DLV-969: our own sign-in and sign-up pages. Each route calls one Cognito user-pool operation and answers with the
 * next step for the page; tokens never leave the Gateway. A successful sign-in builds the same server-side session as
 * the OAuth callback and finishes through {@link GatewaySecurityHandlers#completeSignIn}, so the DEV gate, Domain
 * admission, waiting accounts and sign-in challenges behave identically. CSRF-protected like every BFF POST.
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
@RequestMapping("/bff/api/v1/auth/password")
public class PasswordSignInController {
    static final String PENDING = "lookaheadPasswordChallenge";
    static final int MAX_BODY = 8192;
    /** Cognito keeps a challenge session for three minutes. */
    static final Duration CHALLENGE_WINDOW = Duration.ofMinutes(3);
    record Pending(String username, String challenge, String session, Instant expires, String returnTo) implements java.io.Serializable {}

    private final OAuthSettings settings;
    private final CognitoPasswordClient cognito;
    private final PasswordSignInThrottle throttle;
    private final ClientRegistrationRepository registrations;
    private final JwtDecoderFactory<ClientRegistration> idDecoders;
    private final OAuth2AuthorizedClientRepository clients;
    private final GatewaySecurityHandlers handlers;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();
    private final Clock clock;
    private final JsonMapper json = new JsonMapper();

    @org.springframework.beans.factory.annotation.Autowired
    public PasswordSignInController(OAuthSettings settings,
            ClientRegistrationRepository registrations,
            JwtDecoderFactory<ClientRegistration> idDecoders,
            OAuth2AuthorizedClientRepository clients,
            GatewaySecurityHandlers handlers) {
        this(settings,
            new CognitoPasswordClient(cognitoClient(settings), settings),
            new PasswordSignInThrottle(Clock.systemUTC()),
            registrations, idDecoders, clients, handlers, Clock.systemUTC());
    }
    PasswordSignInController(OAuthSettings settings,
            CognitoPasswordClient cognito,
            PasswordSignInThrottle throttle,
            ClientRegistrationRepository registrations,
            JwtDecoderFactory<ClientRegistration> idDecoders,
            OAuth2AuthorizedClientRepository clients,
            GatewaySecurityHandlers handlers,
            Clock clock) {
        this.settings = settings; this.cognito = cognito; this.throttle = throttle; this.registrations = registrations;
        this.idDecoders = idDecoders; this.clients = clients; this.handlers = handlers; this.clock = clock;
    }

    /** Anonymous: these are Cognito's public client operations, authorised by the client id and SECRET_HASH. */
    static CognitoIdentityProviderClient cognitoClient(OAuthSettings settings) {
        String region = java.net.URI.create(settings.issuer()).getHost().split("\\.")[1];
        return CognitoIdentityProviderClient.builder().region(software.amazon.awssdk.regions.Region.of(region))
            .credentialsProvider(software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider.create())
            .httpClientBuilder(software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(3)).socketTimeout(Duration.ofSeconds(5)))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(8)).apiCallAttemptTimeout(Duration.ofSeconds(5))
                .retryStrategy(software.amazon.awssdk.retries.DefaultRetryStrategy.doNotRetry()))
            .build();
    }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(HttpServletRequest request, HttpServletResponse response) {
        return handle(request, "sign-in.password", body -> {
            String email = email(body), password = secret(body, "password"), returnTo = GatewayConfiguration.safeReturn(text(body, "returnTo", 2048, true));
            if (!throttle.allow("sign-in.password", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            var result = cognito.signIn(email, password);
            return next(request, response, email, returnTo, result.challengeName(), result.session(), result.authenticationResult());
        });
    }

    @PostMapping("/challenge")
    public ResponseEntity<?> challenge(HttpServletRequest request, HttpServletResponse response) {
        return handle(request, "sign-in.challenge", body -> {
            var session = request.getSession(false);
            if (session == null || !(session.getAttribute(PENDING) instanceof Pending pending) || !pending.expires().isAfter(clock.instant())) {
                if (session != null) session.removeAttribute(PENDING);
                return failure(400, "STEP_EXPIRED");
            }
            if (!throttle.allow("sign-in.challenge", address(request), pending.username())) return failure(429, "TOO_MANY_REQUESTS");
            var challenge = ChallengeNameType.fromValue(pending.challenge());
            Map<String, String> answers = switch (challenge) {
                case NEW_PASSWORD_REQUIRED -> Map.of("NEW_PASSWORD", secret(body, "newPassword"));
                case SOFTWARE_TOKEN_MFA -> Map.of("SOFTWARE_TOKEN_MFA_CODE", code(body));
                case EMAIL_OTP -> Map.of("EMAIL_OTP_CODE", code(body));
                default -> throw new IllegalArgumentException("Unsupported challenge");
            };
            var result = cognito.respond(challenge, pending.session(), pending.username(), answers);
            session.removeAttribute(PENDING);
            return next(request, response, pending.username(), pending.returnTo(), result.challengeName(), result.session(), result.authenticationResult());
        });
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> signUp(HttpServletRequest request) {
        return handle(request, "sign-up.started", body -> {
            String email = email(body), password = secret(body, "password"), first = name(body, "firstName"), last = name(body, "lastName");
            if (!throttle.allow("sign-up.started", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            var result = cognito.signUp(email, password, first, last);
            return step("CODE_SENT", destination(result.codeDeliveryDetails(), email));
        });
    }

    @PostMapping("/sign-up/confirm")
    public ResponseEntity<?> confirm(HttpServletRequest request) {
        return handle(request, "sign-up.confirmed", body -> {
            String email = email(body), code = code(body);
            if (!throttle.allow("sign-up.confirmed", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            cognito.confirmSignUp(email, code);
            // The password is never kept between requests, so the person signs in once more after confirming.
            return step("SIGN_IN", null);
        });
    }

    @PostMapping("/sign-up/resend")
    public ResponseEntity<?> resend(HttpServletRequest request) {
        return handle(request, "sign-up.code-resent", body -> {
            String email = email(body);
            if (!throttle.allow("sign-up.code-resent", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            var result = cognito.resend(email);
            return step("CODE_SENT", destination(result.codeDeliveryDetails(), email));
        });
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<?> forgot(HttpServletRequest request) {
        return handle(request, "password-reset.requested", body -> {
            String email = email(body);
            if (!throttle.allow("password-reset.requested", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            try {
                var result = cognito.forgot(email);
                return step("CODE_SENT", destination(result.codeDeliveryDetails(), email));
            } catch (UserNotFoundException | InvalidParameterException unknown) {
                // The same answer whether or not the account exists, so the page cannot be used to probe for accounts.
                return step("CODE_SENT", masked(email));
            }
        });
    }

    @PostMapping("/password/reset")
    public ResponseEntity<?> reset(HttpServletRequest request, HttpServletResponse response) {
        return handle(request, "password-reset.completed", body -> {
            String email = email(body), code = code(body), password = secret(body, "newPassword"), returnTo = GatewayConfiguration.safeReturn(text(body, "returnTo", 2048, true));
            if (!throttle.allow("password-reset.completed", address(request), email)) return failure(429, "TOO_MANY_REQUESTS");
            cognito.reset(email, code, password);
            // The new password is in this request; signing in with it now saves a second form, and nothing is stored.
            var result = cognito.signIn(email, password);
            return next(request, response, email, returnTo, result.challengeName(), result.session(), result.authenticationResult());
        });
    }

    // ----- shared steps -----

    private ResponseEntity<?> next(HttpServletRequest request, HttpServletResponse response, String username, String returnTo,
            ChallengeNameType challenge, String session, AuthenticationResultType tokens) {
        if (tokens != null) {
            String next = finish(request, response, username, returnTo, tokens);
            // DLV-969 S36: the page shows "Check your inbox" itself, so the next path stays the normal one. Only a final
            // destination carries it; a further sign-in step (/sign-in/choose, an error or waiting page) never does.
            boolean merge = GatewaySecurityHandlers.mergeAvailable(request) && GatewayConfiguration.safeReturn(next).equals(next);
            return step("SIGNED_IN", null, next, merge);
        }
        if (challenge == null || session == null || session.isBlank()) {
            // DLV-969: Cognito answered with neither tokens nor a usable next step; the page only sees SERVICE_UNAVAILABLE.
            OpsLog.failed("sign-in.cognito-step", "COGNITO_ANSWER_INCOMPLETE").addKeyValue("cognito.challenge", challenge == null ? "none" : challenge.toString())
                .log("Cognito's sign-in answer had no tokens and {}; answered 503", challenge == null ? "no next step" : "no session for step " + challenge);
            return failure(503, "SERVICE_UNAVAILABLE");
        }
        String kind = switch (challenge) {
            case NEW_PASSWORD_REQUIRED -> "NEW_PASSWORD";
            case SOFTWARE_TOKEN_MFA -> "APP_CODE";
            case EMAIL_OTP -> "EMAIL_CODE";
            default -> null;
        };
        if (kind == null) {
            OpsLog.failed("sign-in.cognito-step", "COGNITO_STEP_UNSUPPORTED").addKeyValue("cognito.challenge", challenge.toString())
                .log("Cognito asked for sign-in step {}, which our sign-in page does not support (check the pool's MFA and sign-in settings); answered 503", challenge);
            return failure(503, "SERVICE_UNAVAILABLE");
        }
        request.getSession(true).setAttribute(PENDING, new Pending(username, challenge.toString(), session, clock.instant().plus(CHALLENGE_WINDOW), returnTo));
        return step(kind, null);
    }

    /** Builds the OAuth-equivalent session from Cognito's tokens and runs the shared completion; returns the next path. */
    String finish(HttpServletRequest request, HttpServletResponse response, String username, String returnTo, AuthenticationResultType tokens) {
        var registration = registrations.findByRegistrationId("lookahead");
        var decoded = idDecoders.createDecoder(registration).decode(tokens.idToken());
        if (!"id".equals(decoded.getClaimAsString("token_use"))) throw new IllegalStateException("Not an ID token");
        var idToken = new OidcIdToken(decoded.getTokenValue(), decoded.getIssuedAt(), decoded.getExpiresAt(), decoded.getClaims());
        List<GrantedAuthority> authorities = List.of(new OidcUserAuthority(idToken), new SimpleGrantedAuthority("SCOPE_aws.cognito.signin.user.admin"));
        var user = new DefaultOidcUser(authorities, idToken, "sub");
        Instant now = clock.instant();
        int lifetime = tokens.expiresIn() == null || tokens.expiresIn() <= 0 ? 300 : tokens.expiresIn();
        var access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokens.accessToken(), now, now.plusSeconds(lifetime), Set.of("aws.cognito.signin.user.admin"));
        var refresh = tokens.refreshToken() == null ? null : new OAuth2RefreshToken(tokens.refreshToken(), now);
        // A fresh session id for the signed-in session, as the OAuth callback does (session fixation).
        var session = request.getSession(true);
        request.changeSessionId();
        session.removeAttribute(PENDING);
        session.setAttribute("learningReturnTo", returnTo);
        var authentication = new OAuth2AuthenticationToken(user, authorities, registration.getRegistrationId());
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registration, authentication.getName(), access, refresh), authentication, request, response);
        return handlers.completeSignIn(request, response, authentication);
    }

    interface Action { ResponseEntity<?> apply(JsonNode body); }

    /** Runs one page route and writes its {@code lookahead.event} line: the outcome and the stable reason, never the input. */
    private ResponseEntity<?> handle(HttpServletRequest request, String event, Action action) {
        JsonNode body;
        try {
            byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
            if (raw.length > MAX_BODY) return outcome(event, failure(413, "REQUEST_TOO_LARGE"), null);
            body = json.readTree(raw);
            if (body == null || !body.isObject()) return outcome(event, failure(400, "INVALID_REQUEST"), null);
        } catch (IOException | RuntimeException unreadable) {
            return outcome(event, failure(400, "INVALID_REQUEST"), null);
        }
        try {
            return outcome(event, action.apply(body), null);
        } catch (IllegalArgumentException invalid) {
            return outcome(event, failure(400, "INVALID_REQUEST"), null);
        } catch (CognitoIdentityProviderException rejected) {
            var answer = mapped(rejected);
            if (answer.getStatusCode().value() == 429)
                OpsLog.limit("cognito", 0, null, event, "Rate limit reached: {} refused by Cognito ({})", event, OpsLog.awsCode(rejected));
            return outcome(event, answer, null);
        } catch (RuntimeException unavailable) {
            return outcome(event, failure(503, "SERVICE_UNAVAILABLE"), RequestLog.types(unavailable));
        }
    }

    /** What each route is, in words, for the log line. */
    private static final Map<String, String> ROUTES = Map.of("sign-in.password", "Password sign-in",
        "sign-in.challenge", "Sign-in step (new password or code)", "sign-up.started", "Sign-up",
        "sign-up.confirmed", "Sign-up code confirmation", "sign-up.code-resent", "Sign-up code resend",
        "password-reset.requested", "Password reset request", "password-reset.completed", "Password reset");
    /** The next step the page is sent to, in words. */
    private static final Map<String, String> STEPS = Map.of("SIGNED_IN", "signed in with Cognito, finishing the sign-in",
        "CODE_SENT", "code sent", "SIGN_IN", "the person signs in next", "NEW_PASSWORD", "Cognito requires a new password",
        "APP_CODE", "Cognito requires an authenticator app code", "EMAIL_CODE", "Cognito requires an emailed code");
    /** Each refusal code, in words. */
    private static final Map<String, String> WHY = Map.ofEntries(Map.entry("INVALID_CREDENTIALS", "wrong email or password"),
        Map.entry("USER_NOT_CONFIRMED", "the account has not confirmed its email yet"), Map.entry("CODE_MISMATCH", "wrong code"),
        Map.entry("CODE_EXPIRED", "the code expired"), Map.entry("INVALID_PASSWORD", "the password breaks the password rules"),
        Map.entry("USERNAME_EXISTS", "an account with this email already exists"), Map.entry("TOO_MANY_REQUESTS", "too many attempts"),
        Map.entry("STEP_EXPIRED", "the sign-in step expired or was already used"), Map.entry("INVALID_REQUEST", "the form was malformed or a field failed validation"),
        Map.entry("REQUEST_TOO_LARGE", "the request was too large"), Map.entry("SERVICE_UNAVAILABLE", "Cognito or the sign-in completion was unavailable or answered unexpectedly"));

    static ResponseEntity<?> outcome(String event, ResponseEntity<?> answer, String types) {
        int status = answer.getStatusCode().value();
        String what = ROUTES.getOrDefault(event, event);
        if (status < 400) {
            String step = answer.getBody() instanceof ApiResponse<?> api && api.data() instanceof Map<?, ?> data && data.get("step") instanceof String value ? value : "DONE";
            OpsLog.success(event).addKeyValue("step", step).log("{} succeeded: {}", what, STEPS.getOrDefault(step, step));
            return answer;
        }
        String reason = answer.getBody() instanceof Map<?, ?> body && body.get("code") instanceof String code ? code : "HTTP_" + status;
        var line = status >= 500 ? OpsLog.failed(event, reason) : OpsLog.refused(event, reason);
        if (types != null) line = line.addKeyValue("exception.types", types);
        line.addKeyValue("http.status", status).log("{} {}: {} ({}){}", what, status >= 500 ? "failed" : "refused", reason,
            WHY.getOrDefault(reason, "HTTP " + status), types == null ? "" : " after " + types);
        return answer;
    }

    /** Cognito's answers in the page's vocabulary; never the provider's own message, which may name the account. */
    static ResponseEntity<?> mapped(CognitoIdentityProviderException rejected) {
        if (rejected instanceof NotAuthorizedException || rejected instanceof UserNotFoundException || rejected instanceof PasswordResetRequiredException)
            return rejected.getMessage() != null && rejected.getMessage().contains("session is expired") ? failure(400, "STEP_EXPIRED") : failure(401, "INVALID_CREDENTIALS");
        if (rejected instanceof UserNotConfirmedException) return failure(409, "USER_NOT_CONFIRMED");
        if (rejected instanceof CodeMismatchException) return failure(400, "CODE_MISMATCH");
        if (rejected instanceof ExpiredCodeException) return failure(400, "CODE_EXPIRED");
        if (rejected instanceof InvalidPasswordException) return failure(400, "INVALID_PASSWORD");
        if (rejected instanceof UsernameExistsException) return failure(409, "USERNAME_EXISTS");
        if (rejected instanceof TooManyRequestsException || rejected instanceof LimitExceededException || rejected instanceof TooManyFailedAttemptsException)
            return failure(429, "TOO_MANY_REQUESTS");
        if (rejected instanceof InvalidParameterException) return failure(400, "INVALID_REQUEST");
        return failure(503, "SERVICE_UNAVAILABLE");
    }

    static ResponseEntity<?> step(String kind, String destination) { return step(kind, destination, null, false); }

    static ResponseEntity<?> step(String kind, String destination, String next, boolean mergeAvailable) {
        var data = new java.util.LinkedHashMap<String, Object>();
        data.put("step", kind);
        if (destination != null) data.put("destination", destination);
        if (next != null) data.put("next", next);
        if (mergeAvailable) data.put("mergeAvailable", true);
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(ApiResponse.success(data));
    }

    static ResponseEntity<?> failure(int status, String code) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").body(Map.of("code", code));
    }

    // ----- input rules: bounded, no control characters; secrets are never echoed back -----

    static String text(JsonNode body, String field, int max, boolean optional) {
        JsonNode node = body.get(field);
        if (node == null || node.isNull()) { if (optional) return null; throw new IllegalArgumentException(field); }
        if (!node.isString()) throw new IllegalArgumentException(field);
        String value = node.asString();
        if (value.length() > max || value.codePoints().anyMatch(Character::isISOControl)) throw new IllegalArgumentException(field);
        return value;
    }
    static String email(JsonNode body) {
        String value = text(body, "email", 254, false).strip();
        if (!value.matches("[^@\\s]{1,64}@[^@\\s]{1,189}\\.[^@\\s]{1,63}")) throw new IllegalArgumentException("email");
        return value.toLowerCase(java.util.Locale.ROOT);
    }
    static String secret(JsonNode body, String field) {
        String value = text(body, field, 256, false);
        if (value.isEmpty()) throw new IllegalArgumentException(field);
        return value;
    }
    static String code(JsonNode body) {
        String value = text(body, "code", 16, false).strip();
        if (!value.matches("[0-9]{6,8}")) throw new IllegalArgumentException("code");
        return value;
    }
    static String name(JsonNode body, String field) {
        String value = text(body, field, 80, false).strip();
        if (value.isEmpty()) throw new IllegalArgumentException(field);
        return value;
    }
    static String destination(CodeDeliveryDetailsType details, String email) {
        return details != null && details.destination() != null && !details.destination().isBlank() ? details.destination() : masked(email);
    }
    static String masked(String email) {
        int at = email.indexOf('@');
        return at <= 0 ? "your email" : email.charAt(0) + "***" + email.substring(at);
    }
    /** The address the request reached the Gateway from: the last X-Forwarded-For hop when present (added by the load balancer). */
    static String address(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] hops = forwarded.split(",");
            String last = hops[hops.length - 1].strip();
            if (!last.isEmpty() && last.length() <= 64) return last;
        }
        return request.getRemoteAddr();
    }
}
