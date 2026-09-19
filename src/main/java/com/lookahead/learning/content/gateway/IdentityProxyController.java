package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import java.io.IOException;
import java.util.List;
import java.util.Set;

/** Public Identity routes only. Identity owns its session, CSRF checks and authentication. */
@RestController
@Profile("gateway")
public class IdentityProxyController {
    public static final String[] PATHS = {"/api/v1/auth/options", "/api/v1/auth/csrf",
            "/api/v1/auth/login", "/api/v1/auth/register", "/api/v1/auth/continue", "/api/v1/auth/logout",
            "/api/v1/account/profile", "/api/v1/account/password",
            "/oauth2/authorize", "/oauth2/token", "/oauth2/jwks", "/oauth2/revoke", "/oauth2/introspect",
            "/connect/logout", "/userinfo", "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server"};
    static final int MAX_BYTES = 1024 * 1024;
    private final OAuthSettings settings;
    private final RestClient http;
    private final String identityCookieName;

    public IdentityProxyController(OAuthSettings settings, RestClient http,
            @org.springframework.beans.factory.annotation.Value("${app.gateway.identity-cookie-name:LOOKAHEAD_SESSION}") String identityCookieName) {
        this.settings = settings;
        this.http = http;
        if (!identityCookieName.matches("[A-Z][A-Z0-9_]{2,63}")) throw new IllegalStateException("Invalid Identity cookie name");
        this.identityCookieName = identityCookieName;
    }

    @RequestMapping(value = {"/api/v1/auth/options", "/api/v1/auth/csrf", "/api/v1/auth/login",
            "/api/v1/auth/register", "/api/v1/auth/continue", "/api/v1/auth/logout", "/oauth2/authorize",
            "/oauth2/token", "/oauth2/jwks", "/oauth2/revoke", "/oauth2/introspect", "/connect/logout",
            "/userinfo", "/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"},
            method = {RequestMethod.GET, RequestMethod.POST})
    public ResponseEntity<byte[]> identity(HttpServletRequest request) throws IOException {
        return forward(request, MAX_BYTES);
    }

    ResponseEntity<byte[]> forward(HttpServletRequest request, int maxBytes) throws IOException {
        String path = request.getRequestURI();
        String origin = request.getHeader("Origin");
        if (origin != null && !origin.equals(settings.frontend())) return empty(403);
        byte[] body = request.getInputStream().readNBytes(maxBytes + 1);
        if (body.length > maxBytes) return empty(413);
        String target = settings.identityUpstream() + path
                + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
        return http.method(HttpMethod.valueOf(request.getMethod())).uri(java.net.URI.create(target)).headers(headers -> {
            for (String name : List.of("Content-Type", "Accept", "X-CSRF-TOKEN")) {
                String value = request.getHeader(name);
                if (value != null) headers.set(name, value);
            }
            if (origin != null) headers.setOrigin(origin);
            // Never forward the Gateway session or arbitrary browser cookies to Identity.
            if (request.getCookies() != null) {
                for (var cookie : request.getCookies()) {
                    if (identityCookieName.equals(cookie.getName())) {
                        headers.set(HttpHeaders.COOKIE, cookie.getName() + "=" + cookie.getValue());
                        break;
                    }
                }
            }
            String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
            boolean clientEndpoint = Set.of("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect").contains(path);
            if (authorization != null && (clientEndpoint && authorization.startsWith("Basic ")
                    || "/userinfo".equals(path) && authorization.startsWith("Bearer ")))
                headers.set(HttpHeaders.AUTHORIZATION, authorization);
        }).body(body).exchange((sent, received) -> {
            byte[] bytes = received.getBody().readNBytes(maxBytes + 1);
            if (bytes.length > maxBytes) return empty(502);
            var headers = new HttpHeaders();
            headers.setCacheControl("no-store");
            headers.set("X-Content-Type-Options", "nosniff");
            for (String name : List.of("Content-Type", "Location", "WWW-Authenticate")) {
                String value = received.getHeaders().getFirst(name);
                if (value != null) headers.set(name, value);
            }
            for (String cookie : received.getHeaders().getOrEmpty(HttpHeaders.SET_COOKIE)) {
                if (cookie.startsWith(identityCookieName + "=")) headers.add(HttpHeaders.SET_COOKIE, cookie);
            }
            return new ResponseEntity<>(bytes, headers, received.getStatusCode());
        });
    }

    private static ResponseEntity<byte[]> empty(int status) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").body(new byte[0]);
    }
}
