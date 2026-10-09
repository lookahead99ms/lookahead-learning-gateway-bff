package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import java.io.IOException;

/** Browser redirects and JSON failure contracts; no token values reach the browser. */
public class GatewaySecurityHandlers {
    private final OAuthSettings settings;

    private org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository clients;
    private org.springframework.web.client.RestClient http;
    public GatewaySecurityHandlers(OAuthSettings settings) { this.settings = settings; }
    @org.springframework.beans.factory.annotation.Autowired
    public GatewaySecurityHandlers(OAuthSettings settings,org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository clients,org.springframework.web.client.RestClient http){this.settings=settings;this.clients=clients;this.http=http;}

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
        if(settings.cloud()) {
            try {
                var client=clients.<org.springframework.security.oauth2.client.OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",authentication,request);
                if(client==null)throw new IllegalStateException("Missing provider tokens");
                CloudGatewaySessions.proof(request,true);
                var admission=new CloudGatewaySessions(settings,http).call("admit",client.getAccessToken().getTokenValue(),request,java.util.Map.of());
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
                clients.removeAuthorizedClient("lookahead",authentication,request,response);session.invalidate();
                org.springframework.security.core.context.SecurityContextHolder.clearContext();
                response.sendRedirect(settings.frontend()+"/sign-in?error=admission");return;
            }
        }
        Object saved = session.getAttribute("learningReturnTo");
        session.removeAttribute("learningReturnTo");
        response.sendRedirect(settings.frontend() + GatewayConfiguration.safeReturn(saved instanceof String value ? value : null));
    }

    void loginFailed(HttpServletRequest request, HttpServletResponse response,
                     AuthenticationException error) throws IOException {
        response.sendRedirect(settings.frontend() + "/sign-in?error=oauth");
    }

    private static void failure(HttpServletResponse response, int status, String body) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.getWriter().write(body);
    }
}
