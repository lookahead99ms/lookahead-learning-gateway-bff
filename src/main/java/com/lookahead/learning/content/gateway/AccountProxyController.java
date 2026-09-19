package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Identity authenticates these self-only operations using its own session and CSRF token. */
@RestController
@Profile("gateway")
public class AccountProxyController {
    static final int MAX_ACCOUNT_BYTES = 8192;
    private final IdentityProxyController identity;
    private final String expiredGatewayCookie;

    public AccountProxyController(IdentityProxyController identity, Environment environment) {
        this.identity = identity;
        var cookie = ResponseCookie.from(environment.getProperty("server.servlet.session.cookie.name", "LOOKAHEAD_GATEWAY"), "")
                .path(environment.getProperty("server.servlet.session.cookie.path", "/"))
                .httpOnly(true)
                .secure(environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, true))
                .sameSite(environment.getProperty("server.servlet.session.cookie.same-site", "Lax"))
                .maxAge(0);
        String domain = environment.getProperty("server.servlet.session.cookie.domain");
        if (domain != null && !domain.isBlank()) cookie.domain(domain);
        expiredGatewayCookie = cookie.build().toString();
    }

    @RequestMapping(value = "/api/v1/account/profile", method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<byte[]> profile(HttpServletRequest request) throws IOException {
        // Spring maps HEAD implicitly to GET; only the published methods reach Identity.
        if (!"GET".equals(request.getMethod()) && !"POST".equals(request.getMethod()))
            return ResponseEntity.status(405).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
        return forward(request);
    }

    @PostMapping("/api/v1/account/password")
    public ResponseEntity<byte[]> password(HttpServletRequest request) throws IOException {
        var response = forward(request);
        if (response.getStatusCode().value() != 200) return response;
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        SecurityContextHolder.clearContext();
        var headers = new HttpHeaders();
        headers.putAll(response.getHeaders());
        headers.add(HttpHeaders.SET_COOKIE, expiredGatewayCookie);
        return new ResponseEntity<>(response.getBody(), headers, response.getStatusCode());
    }

    private ResponseEntity<byte[]> forward(HttpServletRequest request) throws IOException {
        var response = identity.forward(request, MAX_ACCOUNT_BYTES);
        // Infrastructure errors may contain implementation details. Identity's 4xx contract is retained.
        if (response.getStatusCode().is5xxServerError()) {
            return ResponseEntity.status(503).header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .header(HttpHeaders.CONTENT_TYPE, "application/json")
                    .body("{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"The account service is temporarily unavailable. Retry shortly.\"}"
                            .getBytes(StandardCharsets.UTF_8));
        }
        return response;
    }
}
