package com.lookahead.gateway.proxy;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.UpstreamAnswerHeaders;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.Map;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestClient;

/**
 * DLV-969 S36: forwards one account-merge request to the Domain's account routes with the
 * server-held token and sign-in proof, and passes the Domain's status and body through unchanged.
 * The routes are in {@code AccountMergeProxyController}.
 */
public final class AccountMergeProxy {
  static final int MAX_BODY = 16 * 1024;

  /** The candidates answer lists each account's study plans; generous, still bounded. */
  static final int MAX_ANSWER = 1024 * 1024;

  static final String TOKEN = "[A-Za-z0-9_-]{43}";
  private final OAuthClientDetails oauth;
  private final SignInTokenClient tokens;
  private final OAuth2AuthorizedClientRepository clients;
  private final RestClient http;

  public AccountMergeProxy(
      OAuthClientDetails oauth,
      SignInTokenClient tokens,
      OAuth2AuthorizedClientRepository clients,
      RestClient http) {
    this.oauth = oauth;
    this.tokens = tokens;
    this.clients = clients;
    this.http = http;
  }

  /**
   * The two routes that carry the emailed token: a token of another shape is answered 404 here and
   * the Domain is not asked.
   */
  public ResponseEntity<?> forwardWithToken(
      HttpMethod method,
      String token,
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication)
      throws IOException {
    if (!token.matches(TOKEN)) return failure(404, "MERGE_TOKEN_INVALID");
    return forward(method, "/" + token, request, response, authentication);
  }

  public ResponseEntity<?> forward(
      HttpMethod method,
      String suffix,
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication)
      throws IOException {
    // DLV-969: logged as merge.request / merge.candidates / merge.merge, like the other account
    // actions; never the token.
    String event =
        suffix.equals("/request")
            ? "merge.request"
            : method == HttpMethod.GET ? "merge.candidates" : "merge.merge";
    // The same refusals as the other account routes: a session at the sign-in challenge, or a test
    // account.
    if (SignInProofSession.restricted(request))
      return refused(
          event,
          failure(401, "SIGN_IN_CHALLENGE_REQUIRED"),
          "the person must first choose which active sign-in to end");
    if (TestSessionState.active(authentication))
      return refused(
          event, failure(409, "TEST_SESSION"), "a test account never takes part in a merge");
    if (!(authentication instanceof OAuth2AuthenticationToken))
      return refused(
          event, failure(401, "AUTHENTICATION_REQUIRED"), "not signed in with the provider");
    byte[] body =
        method == HttpMethod.POST ? request.getInputStream().readNBytes(MAX_BODY + 1) : null;
    if (body != null && body.length > MAX_BODY)
      return refused(
          event,
          failure(413, "REQUEST_TOO_LARGE"),
          "the body is larger than " + MAX_BODY + " bytes");
    try {
      var client = tokens.authorize(authentication, request, response);
      if (client == null)
        return refused(
            event,
            failure(401, "AUTHENTICATION_REQUIRED"),
            "this session holds no provider tokens");
      var call =
          http.method(method)
              .uri(URI.create(oauth.domainApiUpstream() + "/api/v1/account/merge" + suffix))
              .headers(headers -> {
                headers.setBearerAuth(client.getAccessToken().getTokenValue());
                SignInProofSession.apply(oauth, request, headers);
              });
      if (body != null) call.contentType(MediaType.APPLICATION_JSON).body(body);
      return call.<ResponseEntity<?>>exchange((sent, received) -> {
        byte[] bytes = received.getBody().readNBytes(MAX_ANSWER + 1);
        if (bytes.length > MAX_ANSWER)
          return refused(
              event,
              failure(503, "SERVICE_UNAVAILABLE"),
              "Domain's answer is larger than " + MAX_ANSWER + " bytes");
        int status = received.getStatusCode().value();
        if (status >= 300)
          OpsLog.refusedByUpstream(
              "Merge step {} refused by Domain: {} (HTTP {})", event, event, bytes, status);
        else
          OpsLog.success(event)
              .addKeyValue("upstream.status", status)
              .log(
                  event.equals("merge.request")
                      ? "Merge step {} accepted by Domain: if there is anything to merge, the link"
                          + " is on its way by email"
                      : event.equals("merge.candidates")
                          ? "Merge step {} done: Domain listed the accounts behind the emailed link"
                          : "Merge step {} done: Domain merged the accounts; this sign-in ends",
                  event);
        var headers = UpstreamAnswerHeaders.from(received);
        return new ResponseEntity<>(bytes, headers, received.getStatusCode());
      });
    } catch (RuntimeException error) {
      return AccountCloudProxy.notCompleted(
          error,
          event,
          AccountMergeProxy::refused,
          AccountMergeProxy::failure,
          clients,
          authentication,
          request,
          response);
    }
  }

  /**
   * One WARN line for a merge request the Gateway BFF refused or could not complete: the code and
   * why, never the body or token.
   */
  private static ResponseEntity<?> refused(String event, ResponseEntity<?> answer, String why) {
    return OpsLog.refusedAnswer("Merge step {} refused: {} ({})", event, answer, why);
  }

  public static ResponseEntity<?> failure(int status, String code) {
    return ResponseEntity.status(status)
        .header("Cache-Control", "no-store")
        .contentType(MediaType.APPLICATION_JSON)
        .body(Map.of("code", code));
  }
}
