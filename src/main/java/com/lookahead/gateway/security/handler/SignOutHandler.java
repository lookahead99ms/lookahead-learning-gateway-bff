package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.client.SignInCognitoClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInIdentityClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.client.RestClientException;

/**
 * Signing out, in one class. Sign out on the platform: locally the Identity service revokes the
 * tokens, in the cloud the Domain ends the sign-in and Cognito revokes the refresh token; then the
 * provider's own logout page. Leaving DEV: the sign-in stored on the session is signed out the same
 * way and the session ends whatever happened. The routes are in {@code SignInController} and {@code
 * DevAccessController}; the line for the Sign out route is written by {@code SignOutLog}.
 */
public final class SignOutHandler {
  private final OAuthClientDetails oauth;
  private final SignInTokenClient tokens;
  private final OAuth2AuthorizedClientRepository clients;
  private final SignInDomainClient signInDomainClient;
  private final SignInIdentityClient signInIdentityClient;
  private final SignInCognitoClient signInCognitoClient;
  private final Environment environment;

  public SignOutHandler(
      OAuthClientDetails oauth,
      SignInTokenClient tokens,
      OAuth2AuthorizedClientRepository clients,
      SignInDomainClient signInDomainClient,
      SignInIdentityClient signInIdentityClient,
      SignInCognitoClient signInCognitoClient,
      Environment environment) {
    this.oauth = oauth;
    this.tokens = tokens;
    this.clients = clients;
    this.signInDomainClient = signInDomainClient;
    this.signInIdentityClient = signInIdentityClient;
    this.signInCognitoClient = signInCognitoClient;
    this.environment = environment;
  }

  /**
   * Sign out ({@code POST /bff/api/v1/auth/logout}): the answer names where the browser goes next.
   */
  public ApiResponse<Map<String, String>> logout(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    if (oauth.cloud()) return cloudLogout(request, response, authentication);
    var client =
        clients.loadAuthorizedClient(
            OAuthClientRegistrationFactory.REGISTRATION_ID, authentication, request);
    if (client != null) {
      signInIdentityClient.revoke(client.getAccessToken().getTokenValue());
      if (client.getRefreshToken() != null)
        signInIdentityClient.revoke(client.getRefreshToken().getTokenValue());
    }
    String idToken =
        authentication.getPrincipal() instanceof OidcUser user
            ? user.getIdToken().getTokenValue()
            : null;
    clients.removeAuthorizedClient(
        OAuthClientRegistrationFactory.REGISTRATION_ID, authentication, request, response);
    DevAccessSession.clearLearner(request);
    String url =
        oauth.issuer()
            + "/connect/logout?post_logout_redirect_uri="
            + encode(oauth.frontend() + "/sign-in");
    if (idToken != null) url += "&id_token_hint=" + encode(idToken);
    response.setHeader("Cache-Control", "no-store");
    return ApiResponse.success(Map.of("logoutUrl", url));
  }

  private ApiResponse<Map<String, String>> cloudLogout(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    // DLV-969 (2026-11-04): Sign out from a test session started from your own sign-in signs you
    // out of that sign-in.
    if (TestSessionState.active(authentication)
        && TestSessionState.staffSignIn(request) instanceof OAuth2AuthenticationToken staff)
      authentication = staff;
    // DLV-969 S35: a test session has no provider sign-in; it ends here and the DEV gate stays
    // open.
    if (TestSessionState.active(authentication)) {
      DevAccessSession.clearLearner(request);
      response.setHeader("Cache-Control", "no-store");
      return ApiResponse.success(
          Map.of(
              "logoutUrl", oauth.frontend() + "/sign-in", "providerRevocationConfirmed", "true"));
    }
    var client = tokens.authorize(authentication, request, response);
    boolean providerConfirmed = false;
    if (client != null) {
      var result =
          signInDomainClient.call(
              "logout",
              client.getAccessToken().getTokenValue(),
              SignInProofSession.proof(request, false),
              SignInProofSession.challenge(request),
              Map.of());
      if (result.status() != 200 && result.status() != 401)
        throw new RestClientException("Domain sign-out could not be confirmed");
      if (client.getRefreshToken() != null) {
        try {
          signInCognitoClient.revokeRefreshToken(client.getRefreshToken().getTokenValue());
          providerConfirmed = true;
        } catch (RuntimeException unavailable) {
          /* Durable Domain denial already committed. Report provider uncertainty. */
        }
      }
    }
    clients.removeAuthorizedClient(
        OAuthClientRegistrationFactory.REGISTRATION_ID, authentication, request, response);
    DevAccessSession.clearLearner(request);
    response.setHeader("Cache-Control", "no-store");
    return ApiResponse.success(
        Map.of(
            "logoutUrl",
            oauth.frontend() + "/bff/logout/complete",
            "providerRevocationConfirmed",
            Boolean.toString(providerConfirmed)));
  }

  /**
   * The second step of a cloud sign-out ({@code GET /bff/logout/complete}): on to Cognito's logout
   * page, which returns to the sign-in page.
   */
  public void cloudLogoutComplete(HttpServletResponse response) throws IOException {
    if (!oauth.cloud()) {
      response.setStatus(404);
      return;
    }
    response.setHeader("Cache-Control", "no-store");
    response.sendRedirect(
        oauth.managedLogin()
            + "/logout?client_id="
            + encode(oauth.clientId())
            + "&logout_uri="
            + encode(oauth.frontend() + "/sign-in"));
  }

  /**
   * Leaving DEV ({@code POST /dev/leave}): signs out the sign-in this session holds through {@link
   * #logout}, ends the session whatever happened, and says whether the platform sign-out was
   * confirmed. Both {@code dev-gate.exit} lines are written here, where the sign-out is caught and
   * the session ends.
   */
  public boolean leaveDev(HttpServletRequest request, HttpServletResponse response) {
    // The admission security chain intentionally does not load learner authentication.
    // Read only the existing server-owned learner context for its sign-out operation.
    var session = request.getSession(false);
    Object stored = session == null ? null : session.getAttribute("SPRING_SECURITY_CONTEXT");
    boolean learnerConfirmed = true;
    try {
      if (stored instanceof SecurityContext context
          && context.getAuthentication() instanceof OAuth2AuthenticationToken auth) {
        logout(request, response, auth);
      } else if (TestSessionState.staffSignIn(request) instanceof OAuth2AuthenticationToken staff) {
        // DLV-969: leaving DEV from a test account also ends the staff sign-in kept aside behind
        // it.
        logout(request, response, staff);
      }
    } catch (RuntimeException unavailable) {
      learnerConfirmed = false;
      OpsLog.failed("dev-gate.exit", "SIGN_OUT_UNCONFIRMED")
          .addKeyValue("exception.types", OpsLog.types(unavailable))
          .log(
              "Exit DEV: SIGN_OUT_UNCONFIRMED (the platform sign-out could not be confirmed: {});"
                  + " the session ends anyway",
              OpsLog.types(unavailable));
    } finally {
      var remaining = request.getSession(false);
      if (remaining != null) remaining.invalidate();
      SecurityContextHolder.clearContext();
    }
    OpsLog.success("dev-gate.exit")
        .addKeyValue("signOut.confirmed", learnerConfirmed)
        .log(
            "Exit DEV: the DEV gate closed and the session ended; platform sign-out confirmed: {}",
            learnerConfirmed);
    return learnerConfirmed;
  }

  /**
   * Where the browser goes after leaving DEV: the provider's logout page, which returns to {@code
   * /dev/leave/complete}. Read at each call.
   *
   * <p>Exception, decided 2026-11-25 (DLV-1015): the three values are read from the environment
   * although {@code oauth} holds them too (rule 7: a duplicate read). The two sources are not
   * provably the same: the client id and the frontend reach {@code OAuthClientDetails} through a
   * relaxed binding of {@code app.oauth}, so with a key written in another form (measured: {@code
   * app.oauth.clientId} in a source above the YAML) the details hold that value while the exact key
   * read here still gives the YAML's.
   */
  public String leaveDevUrl() {
    // Log out of the learner provider, which is also the gate's provider since DLV-969. No token
    // travels in a URL.
    return environment.getRequiredProperty("app.cognito.managed-login")
        + "/logout?client_id="
        + encode(environment.getRequiredProperty("app.oauth.client-id"))
        + "&logout_uri="
        + encode(environment.getRequiredProperty("app.oauth.frontend") + "/dev/leave/complete");
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }
}
