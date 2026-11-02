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
        failure(response, 403, "{\"code\":\"REQUEST_REJECTED\",\"message\":\"Refresh the security token and retry\"}");
    }

    void loginSucceeded(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException {
        var session = request.getSession();
        session.setAttribute(LearnerIdleFilter.LAST_ACTIVITY, java.time.Instant.now());
        if(settings.cloud()) {
            // DLV-969 (README decision 2): the DEV gate stays open only for an account Domain admits. The fresh-sign-in
            // check runs first; a refusal below puts back the gate this browser held before, or none for a waiting account.
            Object previousGate=DevAdmission.current(request);
            try {
                if(gate.isPresent()&&authentication.getPrincipal() instanceof OidcUser user)gate.get().admit(request,user);
                var client=clients.<org.springframework.security.oauth2.client.OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",authentication,request);
                if(client==null)throw new IllegalStateException("Missing provider tokens");
                CloudGatewaySessions.proof(request,true);
                var admission=new CloudGatewaySessions(settings,http).call("admit",client.getAccessToken().getTokenValue(),request,java.util.Map.of());
                if(admission.status()==403&&"ACCOUNT_ADMISSION_REQUIRED".equals(new tools.jackson.databind.json.JsonMapper().readTree(admission.body()).path("code").asString("")))throw new AdmissionPending();
                if(admission.status()!=200)throw new IllegalStateException("Domain rejected admission");
                String challenge=admission.data().path("challengeToken").asString("");
                if(!challenge.isEmpty()) {
                    if(!challenge.matches("[A-Za-z0-9_-]{43}"))throw new IllegalStateException("Invalid challenge");
                    session.setAttribute(CloudGatewaySessions.CHALLENGE,challenge);
                    Object saved=session.getAttribute("learningReturnTo");
                    String destination=GatewayConfiguration.safeReturn(saved instanceof String value?value:null);
                    response.sendRedirect(settings.frontend()+"/sign-in/choose?returnTo="+java.net.URLEncoder.encode(destination,java.nio.charset.StandardCharsets.UTF_8));return;
                }
                if(admission.data().path("signInId").asString("").isEmpty())throw new IllegalStateException("Missing admission");
                session.removeAttribute(CloudGatewaySessions.CHALLENGE);
            } catch(RuntimeException rejected) {
                boolean pending=rejected instanceof AdmissionPending;
                clients.removeAuthorizedClient("lookahead",authentication,request,response);
                if(gate.isPresent()) {
                    // A waiting account never rides on a gate opened by an earlier sign-in in this browser.
                    Object kept=pending?null:previousGate;
                    DevAdmission.restore(request,kept);
                    if(pending){response.sendRedirect(settings.frontend()+"/dev/access?access=pending");return;}
                    response.sendRedirect(settings.frontend()+(DevAdmission.open(kept,java.time.Instant.now())?"/sign-in?error=admission":"/dev/access?error=signin"));return;
                }
                // No gate (PROD): end the learner sign-in; a waiting account lands on the landing page notice.
                DevAdmission.clearLearner(request);
                if(pending){response.sendRedirect(settings.frontend()+"/?access=pending");return;}
                response.sendRedirect(settings.frontend()+"/sign-in?error=admission");return;
            }
        }
        Object saved = session.getAttribute("learningReturnTo");
        session.removeAttribute("learningReturnTo");
        response.sendRedirect(settings.frontend() + GatewayConfiguration.safeReturn(saved instanceof String value ? value : null));
    }

    void loginFailed(HttpServletRequest request, HttpServletResponse response,
                     AuthenticationException error) throws IOException {
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
