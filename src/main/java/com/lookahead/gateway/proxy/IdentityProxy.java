package com.lookahead.gateway.proxy;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import org.springframework.http.*;
import org.springframework.web.client.RestClient;

/**
 * Forwards one browser request to the Identity service and shapes its answer: only the request
 * headers and the Identity cookies named here go out, and only the Identity cookies come back. The
 * routes are in {@code IdentityProxyController}.
 */
public final class IdentityProxy {
  private final OAuthClientDetails oauth;
  private final RestClient http;
  private final Set<String> identityCookies;

  public IdentityProxy(
      OAuthClientDetails oauth,
      RestClient http,
      String identityCookieName,
      String bindingCookie,
      String challengeCookie,
      String sessionCookie) {
    this.oauth = oauth;
    this.http = http;
    for (String name : List.of(identityCookieName, bindingCookie, challengeCookie))
      if (!name.matches("[A-Z][A-Z0-9_]{2,63}"))
        throw new IllegalStateException("Invalid Identity cookie name");
    this.identityCookies = Set.of(identityCookieName, bindingCookie, challengeCookie);
    if (identityCookies.contains(sessionCookie))
      throw new IllegalStateException("Identity and Gateway cookies must be distinct");
  }

  public ResponseEntity<byte[]> forward(HttpServletRequest request, int maxBytes)
      throws IOException {
    String path = request.getRequestURI();
    String origin = request.getHeader("Origin");
    if (origin != null && !origin.equals(oauth.frontend())) return empty(403);
    byte[] body = request.getInputStream().readNBytes(maxBytes + 1);
    if (body.length > maxBytes) return empty(413);
    String target =
        oauth.identityUpstream()
            + path
            + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
    return http.method(HttpMethod.valueOf(request.getMethod()))
        .uri(URI.create(target))
        .headers(headers -> {
          for (String name : List.of("Content-Type", "Accept", "X-CSRF-TOKEN")) {
            String value = request.getHeader(name);
            if (value != null) headers.set(name, value);
          }
          if (origin != null) headers.setOrigin(origin);
          // Never forward the Gateway BFF session or arbitrary browser cookies to Identity.
          if (request.getCookies() != null) {
            var selected = new LinkedHashMap<String, String>();
            for (var cookie : request.getCookies()) {
              if (identityCookies.contains(cookie.getName()))
                selected.putIfAbsent(cookie.getName(), cookie.getName() + "=" + cookie.getValue());
            }
            if (!selected.isEmpty())
              headers.set(HttpHeaders.COOKIE, String.join("; ", selected.values()));
          }
          String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
          boolean clientEndpoint =
              Set.of("/oauth2/token", "/oauth2/revoke", "/oauth2/introspect").contains(path);
          if (authorization != null
              && (clientEndpoint && authorization.startsWith("Basic ")
                  || "/userinfo".equals(path) && authorization.startsWith("Bearer ")))
            headers.set(HttpHeaders.AUTHORIZATION, authorization);
        })
        .body(body)
        .exchange((sent, received) -> {
          byte[] bytes = received.getBody().readNBytes(maxBytes + 1);
          if (bytes.length > maxBytes) {
            OpsLog.failed("identity.proxy", "IDENTITY_ANSWER_TOO_LARGE")
                .addKeyValue("upstream.service", "identity")
                .addKeyValue("upstream.status", received.getStatusCode().value())
                .addKeyValue("url.path", OpsLog.path(request))
                .log(
                    "Identity answer for {} {} refused with 502: IDENTITY_ANSWER_TOO_LARGE (larger"
                        + " than {} bytes)",
                    OpsLog.method(request),
                    OpsLog.path(request),
                    maxBytes);
            return empty(502);
          }
          var headers = new HttpHeaders();
          headers.setCacheControl("no-store");
          headers.set("X-Content-Type-Options", "nosniff");
          for (String name : List.of("Content-Type", "Location", "WWW-Authenticate")) {
            String value = received.getHeaders().getFirst(name);
            if (value != null) headers.set(name, value);
          }
          for (String cookie : received.getHeaders().getOrEmpty(HttpHeaders.SET_COOKIE)) {
            if (identityCookies.stream().anyMatch(name -> cookie.startsWith(name + "=")))
              headers.add(HttpHeaders.SET_COOKIE, cookie);
          }
          return new ResponseEntity<>(bytes, headers, received.getStatusCode());
        });
  }

  private static ResponseEntity<byte[]> empty(int status) {
    return ResponseEntity.status(status).header("Cache-Control", "no-store").body(new byte[0]);
  }
}
