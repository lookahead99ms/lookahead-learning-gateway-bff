package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;

/** Browser redirects and JSON failure contracts; no token values reach the browser. */
public class GatewaySecurityHandlers {
    private final OAuthSettings settings;

    private org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository clients;
    private org.springframework.web.client.RestClient http;
    private Optional<DevGate> gate = Optional.empty();
    public GatewaySecurityHandlers(OAuthSettings settings) { this.settings = settings; }
    @org.springframework.beans.factory.annotation.Autowired
    public GatewaySecurityHandlers(OAuthSettings settings,org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository clients,org.springframework.web.client.RestClient http,Optional<DevGate> gate){this.settings=settings;this.clients=clients;this.http=http;this.gate=gate;}

    /** Domain answered 403 ACCOUNT_ADMISSION_REQUIRED: the sign-in worked, the account waits for the owner (DLV-969). */
    static final class AdmissionPending extends IllegalStateException { AdmissionPending(){super("Account admission pending");} }

    /**
     * DLV-971 (owner, 2026-11-06): the Welcome page greets a waiting person by first name. The learner sign-in ends here
     * and no session survives, so the name travels in a short-lived cookie the Welcome page reads once and clears; never
     * in the redirect's URL. Not HttpOnly on purpose (the page reads it); SameSite=Strict, 15 minutes, nothing else in it.
     */
    static final String WELCOME_COOKIE = "lookahead-welcome";
    static final Duration WELCOME_COOKIE_AGE = Duration.ofMinutes(15);
    /** The first name from the provider's claims: given_name, else the first word of name; letters only, at most 40. */
    static String firstName(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof OidcUser user)) return null;
        String given = user.getGivenName();
        String full = user.getFullName();
        String candidate = given != null && !given.isBlank() ? given.strip() : full == null ? "" : full.strip().split("\\s+")[0];
        return candidate.isEmpty() || candidate.length() > 40 || !candidate.matches("[\\p{L}\\p{M}'\\u2019.-]+") ? null : candidate;
    }
    static void welcomeName(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String first = firstName(authentication);
        if (first == null) return;
        var cookie = ResponseCookie.from(WELCOME_COOKIE, URLEncoder.encode(first, StandardCharsets.UTF_8)).path("/")
            .maxAge(WELCOME_COOKIE_AGE).sameSite("Strict").secure(request.isSecure()).httpOnly(false).build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    void authenticationRequired(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationException error) throws IOException {
        failure(response, 401, "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in to continue\"}");
    }

    void accessDenied(HttpServletRequest request, HttpServletResponse response,
                      AccessDeniedException error) throws IOException {
        // DLV-969: which check refused it, as a reason code. Never the exception's type name: the deploy's log check
        // treats that word as a failed start.
        String reason = rejection(error);
        OpsLog.refused("request.rejected", reason).addKeyValue("http.method", RequestLog.method(request)).addKeyValue("url.path", RequestLog.path(request))
                .log("Request rejected with REQUEST_REJECTED: {} {} ({})", RequestLog.method(request), RequestLog.path(request), REJECTIONS.get(reason));
        failure(response, 403, "{\"code\":\"REQUEST_REJECTED\",\"message\":\"Refresh the security token and retry\"}");
    }

    private static final java.util.Map<String, String> REJECTIONS = java.util.Map.of(
            "CSRF_NO_SESSION_TOKEN", "this session holds no CSRF token yet (a new or expired session)",
            "CSRF_TOKEN_MISMATCH", "no CSRF token was sent, or it does not match this session's",
            "CSRF_REJECTED", "the CSRF check failed", "ROUTE_NOT_ALLOWED", "this route or method is not allowed for this sign-in");

    static String rejection(AccessDeniedException error) {
        if (error instanceof org.springframework.security.web.csrf.MissingCsrfTokenException) return "CSRF_NO_SESSION_TOKEN";
        if (error instanceof org.springframework.security.web.csrf.InvalidCsrfTokenException) return "CSRF_TOKEN_MISMATCH";
        if (error instanceof org.springframework.security.web.csrf.CsrfException) return "CSRF_REJECTED";
        return "ROUTE_NOT_ALLOWED";
    }

    /** {@code google} for a Cognito user federated from Google; otherwise {@code password} (the pool's own email and password). */
    static String provider(Authentication authentication) {
        if (authentication.getPrincipal() instanceof OidcUser user) {
            if (user.getClaims().get("identities") instanceof java.util.Collection<?> identities)
                for (Object identity : identities)
                    if (identity instanceof java.util.Map<?, ?> map && "google".equalsIgnoreCase(String.valueOf(map.get("providerName")))) return "google";
            String username = user.getClaimAsString("cognito:username");
            if (username != null && username.toLowerCase(java.util.Locale.ROOT).startsWith("google_")) return "google";
        }
        return "password";
    }

    /** DLV-969 S36: request attribute set when Domain admitted the sign-in and answered {@code mergeAvailable: true}. */
    static final String MERGE_AVAILABLE = "lookaheadMergeAvailable";
    /** DLV-969 S36: session attribute set when a resolved sign-in challenge answered {@code mergeAvailable: true}; used once by /bff/login. */
    static final String MERGE_AFTER_CHALLENGE = "lookaheadMergeAfterChallenge";

    void loginSucceeded(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException {
        String next = completeSignIn(request, response, authentication);
        if (mergeAvailable(request)) {
            // DLV-969 S36: the redirect sign-in cannot show the inbox panel, so the browser goes to the merge offer first.
            OpsLog.success("sign-in.merge-offer").addKeyValue("provider", settings.cloud() ? provider(authentication) : "identity").addKeyValue("via", "oauth")
                    .log("Sign-in completed and other accounts share this person's verified email: redirected to the merge offer page");
            next = mergeOffer(next);
        }
        response.sendRedirect(settings.frontend() + next);
    }

    /** True only after this request's sign-in was admitted with a literal {@code mergeAvailable: true} (DLV-969 S36). */
    static boolean mergeAvailable(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(MERGE_AVAILABLE));
    }

    /** DLV-969 S36: only a JSON boolean {@code true} counts; a string, number or missing field never does. */
    static boolean literalTrue(tools.jackson.databind.JsonNode value) {
        return value != null && value.isBoolean() && value.booleanValue();
    }

    /**
     * DLV-969 S36: a redirect sign-in cannot show the inbox panel, so the merge page offers the email. A merge target that
     * already has its query (safeReturn allows only the email token and/or offer=1) stays; a bare /account/merge gets the offer.
     */
    static String mergeOffer(String next) {
        if (next.startsWith("/account/merge?")) return next;
        return "/account/merge?offer=1";
    }

    /**
     * The one sign-in completion shared by the OAuth callback and our own password page (DLV-969): DEV gate freshness,
     * Domain admission, waiting accounts and sign-in challenges. Returns the same-origin path the browser goes to next;
     * the OAuth callback redirects to it, the password route returns it as JSON.
     */
    String completeSignIn(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        var session = request.getSession();
        session.setAttribute(LearnerIdleFilter.LAST_ACTIVITY, java.time.Instant.now());
        // DLV-969: which provider and which door (the OAuth callback or our own password page), for the log line.
        String provider = settings.cloud() ? provider(authentication) : "identity";
        String via = request.getRequestURI() != null && request.getRequestURI().startsWith("/login/oauth2/code/") ? "oauth" : "password-page";
        if(settings.cloud()) {
            // DLV-969 (README decision 2): the DEV gate stays open only for an account Domain admits. The fresh-sign-in
            // check runs first; a refusal below puts back the gate this browser held before, or none for a waiting account.
            Object previousGate=DevAdmission.current(request);
            // The step that refused the sign-in, as a stable code for the log line; set before each step that can refuse.
            String reason="DEV_GATE_REFUSED";
            Integer domainStatus=null;
            try {
                if(gate.isPresent()&&authentication.getPrincipal() instanceof OidcUser user)gate.get().admit(request,user);
                reason="MISSING_PROVIDER_TOKENS";
                var client=clients.<org.springframework.security.oauth2.client.OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",authentication,request);
                if(client==null)throw new IllegalStateException("Missing provider tokens");
                CloudGatewaySessions.proof(request,true);
                reason="DOMAIN_UNAVAILABLE";
                var admission=new CloudGatewaySessions(settings,http).call("admit",client.getAccessToken().getTokenValue(),request,java.util.Map.of());
                domainStatus=admission.status();
                if(admission.status()!=200){String code=OpsLog.code(admission.body());reason=code==null?"DOMAIN_REFUSED":code;}
                if(admission.status()==403&&"ACCOUNT_ADMISSION_REQUIRED".equals(new tools.jackson.databind.json.JsonMapper().readTree(admission.body()).path("code").asString("")))throw new AdmissionPending();
                if(admission.status()!=200)throw new IllegalStateException("Domain rejected admission");
                reason="INVALID_DOMAIN_ANSWER";
                String challenge=admission.data().path("challengeToken").asString("");
                // DLV-969 S36: a fresh admission decides afresh; an offer left by an earlier challenge never carries over.
                request.getSession().removeAttribute(MERGE_AFTER_CHALLENGE);
                if(!challenge.isEmpty()) {
                    // DLV-969 S36: still at the challenge, so no offer yet; the replace answer carries it once resolved.
                    if(!challenge.matches("[A-Za-z0-9_-]{43}"))throw new IllegalStateException("Invalid challenge");
                    session=request.getSession();
                    session.setAttribute(CloudGatewaySessions.CHALLENGE,challenge);
                    Object saved=session.getAttribute("learningReturnTo");
                    String destination=GatewayConfiguration.safeReturn(saved instanceof String value?value:null);
                    OpsLog.success("sign-in.completed").addKeyValue("provider",provider).addKeyValue("via",via).addKeyValue("next","SIGN_IN_CHALLENGE")
                        .log("Sign-in accepted ({} via {}), but the person must first choose which active sign-in to end (sign-in limit reached)",provider,via);
                    return "/sign-in/choose?returnTo="+java.net.URLEncoder.encode(destination,java.nio.charset.StandardCharsets.UTF_8);
                }
                if(admission.data().path("signInId").asString("").isEmpty())throw new IllegalStateException("Missing admission");
                request.getSession().removeAttribute(CloudGatewaySessions.CHALLENGE);
                // DLV-969 S36: only an admitted sign-in (never a waiting or challenged one) carries the merge offer on.
                boolean merge=literalTrue(admission.data().path("mergeAvailable"));
                if(merge)request.setAttribute(MERGE_AVAILABLE,Boolean.TRUE);
                OpsLog.success("sign-in.completed").addKeyValue("provider",provider).addKeyValue("via",via).addKeyValue("merge.available",merge)
                    .log(merge?"Sign-in completed ({} via {}): Domain admitted the account and other accounts share its verified email (merge offered)"
                        :"Sign-in completed ({} via {}): Domain admitted the account",provider,via);
            } catch(RuntimeException rejected) {
                boolean pending=rejected instanceof AdmissionPending;
                if(pending)reason="ACCOUNT_ADMISSION_REQUIRED";
                var line=("DOMAIN_UNAVAILABLE".equals(reason)?OpsLog.failed("sign-in.completed",reason):OpsLog.refused("sign-in.completed",reason))
                    .addKeyValue("provider",provider).addKeyValue("via",via);
                if(domainStatus!=null)line=line.addKeyValue("upstream.status",domainStatus);
                if(pending)line.log("Sign-in refused by Domain ({} via {}): ACCOUNT_ADMISSION_REQUIRED, the account is waiting for the owner to admit it",provider,via);
                else if("DOMAIN_UNAVAILABLE".equals(reason))line.addKeyValue("exception.types",RequestLog.types(rejected))
                    .log("Sign-in failed ({} via {}): Domain did not answer the admission check ({})",provider,via,RequestLog.types(rejected));
                else line.log("Sign-in refused ({} via {}): {}",provider,via,reason);
                clients.removeAuthorizedClient("lookahead",authentication,request,response);
                if(pending)welcomeName(request,response,authentication);
                if(gate.isPresent()) {
                    // A waiting account never rides on a gate opened by an earlier sign-in in this browser.
                    Object kept=pending?null:previousGate;
                    DevAdmission.restore(request,kept);
                    // DLV-969: a waiting account sees the Look Ahead essence on /welcome while it waits; the gate card
                    // /dev/access?access=pending still renders the same notice as a fallback.
                    if(pending)return "/welcome?access=pending";
                    return DevAdmission.open(kept,java.time.Instant.now())?"/sign-in?error=admission":"/dev/access?error=signin";
                }
                // No gate (PROD): end the learner sign-in; a waiting account lands on the landing page notice.
                DevAdmission.clearLearner(request);
                if(pending)return "/?access=pending";
                return "/sign-in?error=admission";
            }
        }
        session = request.getSession();
        Object saved = session.getAttribute("learningReturnTo");
        session.removeAttribute("learningReturnTo");
        if (!settings.cloud()) OpsLog.success("sign-in.completed").addKeyValue("provider", provider).addKeyValue("via", via)
                .log("Sign-in completed ({} via {})", provider, via);
        return GatewayConfiguration.safeReturn(saved instanceof String value ? value : null);
    }

    void loginFailed(HttpServletRequest request, HttpServletResponse response,
                     AuthenticationException error) throws IOException {
        // DLV-969: the OAuth error code (invalid_state_parameter, access_denied, ...) is a fixed vocabulary; its description is not logged.
        String code = error instanceof org.springframework.security.oauth2.core.OAuth2AuthenticationException oauth && oauth.getError() != null
                && oauth.getError().getErrorCode() != null && oauth.getError().getErrorCode().matches("[a-z_]{1,64}")
                ? oauth.getError().getErrorCode() : "authentication_failed";
        // The cause types (a key, the message is unchanged) say whether Cognito answered no or could not be reached for the
        // token, JWKS or user-info call; never a message.
        OpsLog.refused("sign-in.oauth", "OAUTH_" + code.toUpperCase(java.util.Locale.ROOT)).addKeyValue("oauth.code", code)
                .addKeyValue("exception.types", RequestLog.types(error))
                .log("OAuth sign-in failed at the callback: {}", code);
        // Outside an open DEV gate the Web sign-in page is unreachable, so the gate page carries the message (DLV-969).
        if (gate.isPresent() && !DevAdmission.open(DevAdmission.current(request), java.time.Instant.now())) {
            response.sendRedirect(settings.frontend() + "/dev/access?error=signin"); return;
        }
        response.sendRedirect(settings.frontend() + "/sign-in?error=oauth");
    }

    private static void failure(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(body);
    }
}
