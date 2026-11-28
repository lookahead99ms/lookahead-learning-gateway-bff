package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.DevAccessGate;
import com.lookahead.gateway.security.session.DevAccessSession;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

/**
 * Browser redirects and JSON failure contracts for a refused request or a failed OAuth sign-in; no
 * token values reach the browser.
 */
public final class SignInFailureHandler {
  private final OAuthClientDetails oauth;

  private final Optional<DevAccessGate> gate;

  public SignInFailureHandler(OAuthClientDetails oauth, Optional<DevAccessGate> gate) {
    this.oauth = oauth;
    this.gate = gate;
  }

  public void authenticationRequired(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException error)
      throws IOException {
    failure(
        response,
        401,
        "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in to continue\"}");
  }

  public void accessDenied(
      HttpServletRequest request, HttpServletResponse response, AccessDeniedException error)
      throws IOException {
    // DLV-969: which check refused it, as a reason code. Never the exception's type name: the
    // deploy's log check treats that word as a failed start.
    String reason = rejection(error);
    OpsLog.refused("request.rejected", reason)
        .addKeyValue("http.method", OpsLog.method(request))
        .addKeyValue("url.path", OpsLog.path(request))
        .log(
            "Request rejected with REQUEST_REJECTED: {} {}: {} ({})",
            OpsLog.method(request),
            OpsLog.path(request),
            reason,
            REJECTIONS.get(reason));
    failure(
        response,
        403,
        "{\"code\":\"REQUEST_REJECTED\",\"message\":\"Refresh the security token and retry\"}");
  }

  private static final Map<String, String> REJECTIONS =
      Map.of(
          "CSRF_NO_SESSION_TOKEN",
          "this session holds no CSRF token yet (a new or expired session)",
          "CSRF_TOKEN_MISMATCH",
          "no CSRF token was sent, or it does not match this session's",
          "CSRF_REJECTED",
          "the CSRF check failed",
          "ROUTE_NOT_ALLOWED",
          "this route or method is not allowed for this sign-in");

  static String rejection(AccessDeniedException error) {
    if (error instanceof MissingCsrfTokenException) return "CSRF_NO_SESSION_TOKEN";
    if (error instanceof InvalidCsrfTokenException) return "CSRF_TOKEN_MISMATCH";
    if (error instanceof CsrfException) return "CSRF_REJECTED";
    return "ROUTE_NOT_ALLOWED";
  }

  public void loginFailed(
      HttpServletRequest request, HttpServletResponse response, AuthenticationException error)
      throws IOException {
    // DLV-969: the OAuth error code (invalid_state_parameter, access_denied, ...) is a fixed
    // vocabulary; its description is not logged.
    String code =
        OpsLog.oauthCode(
            error instanceof OAuth2AuthenticationException failed ? failed.getError() : null,
            "authentication_failed");
    // The cause types (a key, the message is unchanged) say whether Cognito answered no or could
    // not be reached for the token, JWKS or user-info call; never a message.
    OpsLog.refused("sign-in.oauth", "OAUTH_" + code.toUpperCase(Locale.ROOT))
        .addKeyValue("oauth.code", code)
        .addKeyValue("exception.types", OpsLog.types(error))
        .log(
            "OAuth sign-in failed at the callback (via oauth): OAUTH_{} (the provider or the"
                + " callback check answered {}; {})",
            code.toUpperCase(Locale.ROOT),
            code,
            OpsLog.types(error));
    // Outside an open DEV gate the Web sign-in page is unreachable, so the gate page carries the
    // message (DLV-969).
    if (gate.isPresent()
        && !DevAccessSession.open(DevAccessSession.current(request), Instant.now())) {
      response.sendRedirect(oauth.frontend() + "/dev/access?error=signin");
      return;
    }
    response.sendRedirect(oauth.frontend() + "/sign-in?error=oauth");
  }

  private static void failure(HttpServletResponse response, int status, String body)
      throws IOException {
    response.setStatus(status);
    response.setContentType("application/json");
    response.setHeader("Cache-Control", "no-store");
    response.getWriter().write(body);
  }
}
