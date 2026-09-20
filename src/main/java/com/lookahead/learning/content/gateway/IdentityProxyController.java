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
            "/api/v1/account/sign-ins", "/api/v1/account/sign-ins/revoke",
            "/api/v1/account/sign-ins/revoke-others", "/api/v1/account/sign-ins/label",
            "/api/v1/auth/sign-in-challenge", "/api/v1/auth/sign-in-challenge/replace",
            "/api/v1/auth/sign-in-challenge/cancel",
            "/oauth2/authorize", "/oauth2/token", "/oauth2/jwks", "/oauth2/revoke", "/oauth2/introspect",
            "/connect/logout", "/userinfo", "/.well-known/openid-configuration",
            "/.well-known/oauth-authorization-server"};
    static final int MAX_BYTES = 1024 * 1024;
    private final OAuthSettings settings;
    private final RestClient http;
    private final Set<String> identityCookies;

    public IdentityProxyController(OAuthSettings settings, RestClient http, String identityCookieName) {
        this(settings, http, identityCookieName, "LOOKAHEAD_SIGNIN_BINDING", "LOOKAHEAD_SIGNIN_CHALLENGE");
    }

    public IdentityProxyController(OAuthSettings settings, RestClient http, String identityCookieName,
            String bindingCookie, String challengeCookie) {
        this(settings, http, identityCookieName, bindingCookie, challengeCookie, "LOOKAHEAD_GATEWAY");
    }

    @org.springframework.beans.factory.annotation.Autowired
    public IdentityProxyController(OAuthSettings settings, RestClient http,
            @org.springframework.beans.factory.annotation.Value("${app.gateway.identity-cookie-name:LOOKAHEAD_SESSION}") String identityCookieName,
            @org.springframework.beans.factory.annotation.Value("${app.gateway.sign-in-binding-cookie-name:LOOKAHEAD_SIGNIN_BINDING}") String bindingCookie,
            @org.springframework.beans.factory.annotation.Value("${app.gateway.sign-in-challenge-cookie-name:LOOKAHEAD_SIGNIN_CHALLENGE}") String challengeCookie,
            @org.springframework.beans.factory.annotation.Value("${server.servlet.session.cookie.name:LOOKAHEAD_GATEWAY}") String gatewayCookie) {
        this.settings = settings;
        this.http = http;
        for (String name : List.of(identityCookieName, bindingCookie, challengeCookie))
            if (!name.matches("[A-Z][A-Z0-9_]{2,63}")) throw new IllegalStateException("Invalid Identity cookie name");
        this.identityCookies = Set.of(identityCookieName, bindingCookie, challengeCookie);
        if (identityCookies.contains(gatewayCookie)) throw new IllegalStateException("Identity and Gateway cookies must be distinct");
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
                var selected = new java.util.LinkedHashMap<String, String>();
                for (var cookie : request.getCookies()) {
                    if (identityCookies.contains(cookie.getName()))
                        selected.putIfAbsent(cookie.getName(), cookie.getName() + "=" + cookie.getValue());
                }
                if (!selected.isEmpty()) headers.set(HttpHeaders.COOKIE, String.join("; ", selected.values()));
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
                if (identityCookies.stream().anyMatch(name -> cookie.startsWith(name + "="))) headers.add(HttpHeaders.SET_COOKIE, cookie);
            }
            return new ResponseEntity<>(bytes, headers, received.getStatusCode());
        });
    }

    private static ResponseEntity<byte[]> empty(int status) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").body(new byte[0]);
    }
}
