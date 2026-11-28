package com.lookahead.gateway.controller;

import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.dto.CsrfView;
import com.lookahead.gateway.security.oauth.SignInProvider;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

/**
 * DLV-1015: the two routes our sign-in page asks before anyone is signed in, in DEV and PROD: which
 * sign-in options to show, and the CSRF token. Moved unchanged from {@link AccountCloudController};
 * locally the same paths are served by {@link IdentityProxyController}.
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression(
    "'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
public class SignInOptionsController {
  private final boolean google;

  @Autowired
  public SignInOptionsController(Environment environment) {
    this(SignInProvider.googleEnabled(environment));
  }

  SignInOptionsController(boolean google) {
    this.google = google;
  }

  /**
   * DLV-969: {@code google} is true once the pool has the Google provider; {@code password} and
   * {@code registration} tell our sign-in page to show its own email-and-password and sign-up forms
   * (Cognito works behind them).
   */
  @GetMapping("/api/v1/auth/options")
  public ApiResponse<?> options(HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    return ApiResponse.success(
        Map.of(
            "registration",
            true,
            "password",
            true,
            "google",
            google,
            "oauth",
            true,
            "managedLogin",
            true));
  }

  @GetMapping("/api/v1/auth/csrf")
  public ApiResponse<CsrfView> csrf(CsrfToken token, HttpServletResponse response) {
    response.setHeader("Cache-Control", "no-store");
    return ApiResponse.success(CsrfView.from(token));
  }
}
