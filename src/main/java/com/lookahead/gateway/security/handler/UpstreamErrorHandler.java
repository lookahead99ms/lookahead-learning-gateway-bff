package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.controller.AccountIdentityController;
import com.lookahead.gateway.controller.DomainProxyController;
import com.lookahead.gateway.controller.IdentityProxyController;
import com.lookahead.gateway.controller.SignInController;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.log.RequestLog;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClientException;

@RestControllerAdvice(
    assignableTypes = {
      SignInController.class,
      DomainProxyController.class,
      IdentityProxyController.class,
      AccountIdentityController.class
    })
@Profile("gateway")
@Order(-100)
public class UpstreamErrorHandler {
  @ExceptionHandler(OAuth2AuthorizationException.class)
  public ResponseEntity<?> expired(OAuth2AuthorizationException error, HttpServletRequest request) {
    // DLV-969: the OAuth error code (invalid_grant, ...) is a fixed vocabulary; its description is
    // not logged.
    String code = OpsLog.oauthCode(error.getError(), "unknown");
    OpsLog.refused("sign-in.session", "SESSION_EXPIRED")
        .addKeyValue("oauth.code", code)
        .addKeyValue("http.method", OpsLog.method(request))
        .addKeyValue("url.path", OpsLog.path(request))
        .log(
            "Session expired for {} {}: the provider refused to renew the sign-in ({}); the person"
                + " must sign in again",
            OpsLog.method(request),
            OpsLog.path(request),
            code);
    return ResponseEntity.status(401)
        .header("Cache-Control", "no-store")
        .body(Map.of("code", "SESSION_EXPIRED", "message", "Sign in again to continue."));
  }

  /**
   * The caller sees only "unavailable" (the request ID is in its X-Request-Id header). The failure
   * itself is an ERROR line at the end of the request ({@link RequestLog}): the outbound
   * interceptor already recorded what failed and where; a RestClientException that did not come
   * through it (an unreadable Domain answer, a mapping failure) is recorded here with its type and
   * message, and the line says the browser got 503 SERVICE_UNAVAILABLE.
   */
  @ExceptionHandler(RestClientException.class)
  public ResponseEntity<?> unavailable(RestClientException error, HttpServletRequest request) {
    if (!RequestLog.upstreamFailurePending())
      RequestLog.upstreamFailed(
          new OpsLog.Failure(
              "upstream",
              OpsLog.method(request) + " " + OpsLog.path(request),
              null,
              -1,
              null,
              null,
              error,
              "UPSTREAM_CALL_FAILED"));
    return ResponseEntity.status(503)
        .header("Cache-Control", "no-store")
        .body(
            Map.of(
                "code",
                "SERVICE_UNAVAILABLE",
                "message",
                "The account service is temporarily unavailable. Retry shortly."));
  }
}
