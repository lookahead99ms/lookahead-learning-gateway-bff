package com.lookahead.learning.content.gateway;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.ResponseEntity;
import org.springframework.core.env.Environment;
import java.util.Map;

@RestController @Profile("lower-cost-dev")
public final class DevAccessController {
    private final Environment environment;
    private final GatewayController learner;
    public DevAccessController(Environment environment, GatewayController learner) { this.environment = environment; this.learner = learner; }
    @GetMapping(value="/dev/access", produces="text/html")
    ResponseEntity<String> access() {
        return ResponseEntity.ok().header("Cache-Control", "no-store").header("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            .body("<!doctype html><html lang=\"en\"><title>DEV access</title><h1>Look Ahead DEV</h1><p>Authorized testers only.</p><a href=\"/dev/oauth2/authorization/admission\">Sign in to DEV</a></html>");
    }
    @GetMapping("/dev/csrf") ResponseEntity<Map<String,String>> csrf(CsrfToken token) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(Map.of("headerName", token.getHeaderName(), "token", token.getToken()));
    }
    @PostMapping("/dev/leave") ResponseEntity<Map<String,String>> leave(HttpServletRequest request, HttpServletResponse response) {
        // The admission security chain intentionally does not load learner authentication.
        // Read only the existing server-owned learner context for its sign-out operation.
        var session = request.getSession(false);
        Object stored = session == null ? null : session.getAttribute("SPRING_SECURITY_CONTEXT");
        boolean learnerConfirmed = true;
        try {
            if (stored instanceof org.springframework.security.core.context.SecurityContext context
                    && context.getAuthentication() instanceof org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken auth) {
                learner.logout(request, response, auth);
            }
        } catch (RuntimeException unavailable) {
            learnerConfirmed = false;
        } finally {
            var remaining = request.getSession(false);
            if (remaining != null) remaining.invalidate();
            org.springframework.security.core.context.SecurityContextHolder.clearContext();
        }
        // Log out of the learner provider, then the admission provider. No token travels in a URL.
        String target = environment.getRequiredProperty("app.cognito.managed-login") + "/logout?client_id="
            + encode(environment.getRequiredProperty("app.oauth.client-id")) + "&logout_uri="
            + encode(environment.getRequiredProperty("app.oauth.frontend") + "/dev/leave/complete");
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(Map.of("logoutUrl", target,
            "learnerSignOutConfirmed", Boolean.toString(learnerConfirmed), "providerRevocationConfirmed", "false"));
    }
    @GetMapping("/dev/leave/complete") void complete(HttpServletResponse response) throws java.io.IOException {
        response.setHeader("Cache-Control", "no-store");
        response.sendRedirect(environment.getRequiredProperty("app.admission.managed-login") + "/logout?client_id="
            + encode(environment.getRequiredProperty("app.admission.client-id")) + "&logout_uri="
            + encode(environment.getRequiredProperty("app.oauth.frontend") + "/dev/access"));
    }
    private static String encode(String s){return java.net.URLEncoder.encode(s,java.nio.charset.StandardCharsets.UTF_8);}
}
