package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import java.io.IOException;
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

    void loginSucceeded(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException {
        response.sendRedirect(settings.frontend() + completeSignIn(request, response, authentication));
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
                if(!challenge.isEmpty()) {
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
                OpsLog.success("sign-in.completed").addKeyValue("provider",provider).addKeyValue("via",via)
                    .log("Sign-in completed ({} via {}): Domain admitted the account",provider,via);
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
        OpsLog.refused("sign-in.oauth", "OAUTH_" + code.toUpperCase(java.util.Locale.ROOT)).addKeyValue("oauth.code", code)
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
