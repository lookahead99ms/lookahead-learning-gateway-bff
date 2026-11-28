package com.lookahead.gateway.proxy;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.UpstreamAnswerHeaders;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.client.RestClient;

/**
 * Relays one allowed request to the Domain and shapes its answer: the server-held token and sign-in
 * proof for a signed-in person, or the test-session headers. Which routes are allowed, who may call
 * them and how large a body may be is decided in {@code DomainProxyRoutes}; the refusals are
 * answered here, before the Domain is asked.
 */
public final class DomainProxy {
  private final OAuthClientDetails oauth;
  private final SignInTokenClient tokens;
  private final RestClient http;

  public DomainProxy(OAuthClientDetails oauth, SignInTokenClient tokens, RestClient http) {
    this.oauth = oauth;
    this.tokens = tokens;
    this.http = http;
  }

  /**
   * Answers what this application refuses itself (405, 404, 401, 413), reads the body within the
   * route's limit and forwards the rest.
   */
  public ResponseEntity<byte[]> relay(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    var match = DomainProxyRoutes.match(request);
    // PUT exists only for platform reviews and delivery work items; every other route keeps its
    // earlier methods.
    if (match.methodRefused())
      return ResponseEntity.status(405).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
    if (match.unknown()) return ResponseEntity.notFound().build();
    boolean testSession = oauth.cloud() && TestSessionState.active(authentication);
    // DLV-971: the delivery plan, promoting a review onto it and running the sweeps are staff work.
    // A test account is a learner, so a test session is refused as Previews/Architecture refuse it
    // (AuthorPreviewProxy): HTTP 401, empty body, Domain not asked.
    if (match.testSessionRefused() && testSession) return PrivateAnswer.empty(401);
    if (match.staffOnly() && !(authentication instanceof OAuth2AuthenticationToken) && !testSession)
      return ResponseEntity.status(401).build();
    byte[] body = request.getInputStream().readNBytes(match.bodyLimit() + 1);
    if (body.length > match.bodyLimit()) return ResponseEntity.status(413).build();
    return forward(
        request,
        response,
        authentication,
        match.upstreamPath(),
        body,
        testSession,
        match.execution());
  }

  public ResponseEntity<byte[]> forward(
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication,
      String upstreamPath,
      byte[] body,
      boolean testSession,
      boolean execution) {
    String target =
        oauth.domainApiUpstream()
            + upstreamPath
            + (request.getQueryString() == null ? "" : "?" + request.getQueryString());
    var outgoing =
        http.method(HttpMethod.valueOf(request.getMethod()))
            .uri(URI.create(target))
            .headers(headers -> {
              for (String name :
                  List.of(
                      "Content-Type",
                      "Accept",
                      "Idempotency-Key",
                      "If-Match",
                      "X-LookAhead-Account")) {
                String value = request.getHeader(name);
                if (value != null) headers.set(name, value);
              }
            });
    if (authentication instanceof OAuth2AuthenticationToken) {
      var client = tokens.authorize(authentication, request, response);
      if (client == null) return ResponseEntity.status(401).build();
      outgoing.headers(headers -> {
        headers.setBearerAuth(client.getAccessToken().getTokenValue());
        SignInProofSession.apply(oauth, request, headers);
      });
    } else if (testSession) {
      // DLV-969 S35: the Domain acts as the test account only with the Gateway BFF secret and this
      // session's gate holder.
      var session = new HttpHeaders();
      if (!TestSessionState.apply(oauth, request, authentication, session))
        return ResponseEntity.status(401).build();
      outgoing.headers(headers -> headers.addAll(session));
    }
    // No browser Authorization, Cookie, Origin, forwarding headers, or arbitrary upstream is
    // relayed.
    return outgoing
        .body(body)
        .exchange((sent, received) -> {
          int responseLimit = execution ? 512 * 1024 : 16 * 1024 * 1024;
          byte[] bytes = received.getBody().readNBytes(responseLimit + 1);
          if (bytes.length > responseLimit) return ResponseEntity.status(502).body(new byte[0]);
          var headers = UpstreamAnswerHeaders.from(received);
          return new ResponseEntity<>(bytes, headers, received.getStatusCode());
        });
  }
}
