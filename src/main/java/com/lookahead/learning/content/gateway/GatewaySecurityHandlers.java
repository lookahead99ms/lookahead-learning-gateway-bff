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

    public GatewaySecurityHandlers(OAuthSettings settings) { this.settings = settings; }

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
