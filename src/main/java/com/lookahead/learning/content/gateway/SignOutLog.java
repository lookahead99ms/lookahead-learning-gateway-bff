package com.lookahead.learning.content.gateway;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * DLV-969 (owner, 2026-11-04): one {@code lookahead.event} line for each Sign out ({@code POST /bff/api/v1/auth/logout}).
 * The sign-out itself lives in {@link GatewayController}, whose exact source is pinned by a reviewed security exception,
 * so it is observed here instead: runs after Spring Security (a request refused for its CSRF token never gets here),
 * reads who was signed in before the controller runs and the answer's status after. Never who; test account ids only.
 */
@Component @Profile("gateway")
public final class SignOutLog extends OncePerRequestFilter {
    static final String PATH = "/bff/api/v1/auth/logout";

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        return !("POST".equals(request.getMethod()) && PATH.equals(request.getRequestURI()));
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication before = SecurityContextHolder.getContext().getAuthentication();
        boolean kept = TestSessionController.staffSignIn(request) != null;
        chain.doFilter(request, response);
        int status = response.getStatus();
        String kind = before instanceof TestSessionController.TestSession ? (kept ? "test-session-and-staff" : "test-session")
                : before instanceof OAuth2AuthenticationToken ? "sign-in" : "none";
        if (status >= 400) {
            (status >= 500 ? OpsLog.failed("sign-out", status == 503 ? "SERVICE_UNAVAILABLE" : "HTTP_" + status)
                    : OpsLog.refused("sign-out", "HTTP_" + status)).addKeyValue("signOut.kind", kind).addKeyValue("http.status", status)
                    .log("Sign out did not complete: HTTP {} ({})", status, status >= 500
                            ? "Domain could not confirm the sign-out; the person stays signed in and can retry" : "refused");
            return;
        }
        var line = OpsLog.success("sign-out").addKeyValue("signOut.kind", kind);
        switch (kind) {
            case "test-session" -> line.addKeyValue("testAccount.id", before.getName())
                    .log("Signed out of test account {}; the DEV gate stays open", before.getName());
            case "test-session-and-staff" -> line.addKeyValue("testAccount.id", before.getName())
                    .log("Signed out of test account {} and of the staff sign-in kept behind it", before.getName());
            case "sign-in" -> line.log("Signed out: Domain ended the sign-in and the provider tokens were dropped");
            default -> line.log("Sign out with no sign-in in this session");
        }
    }
}
