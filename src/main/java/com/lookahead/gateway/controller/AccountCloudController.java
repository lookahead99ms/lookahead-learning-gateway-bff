package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.AccountCloudProxy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("gateway")
@ConditionalOnExpression(
    "'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
public class AccountCloudController {
  private final AccountCloudProxy accounts;

  public AccountCloudController(AccountCloudProxy accounts) {
    this.accounts = accounts;
  }

  @GetMapping({
    "/api/v1/account/sign-ins",
    "/api/v1/auth/sign-in-challenge",
    "/api/v1/account/profile"
  })
  public ResponseEntity<?> read(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    return accounts.forward(request, response, authentication, null);
  }

  @PostMapping({
    "/api/v1/account/sign-ins/revoke",
    "/api/v1/account/sign-ins/revoke-others",
    "/api/v1/account/sign-ins/label",
    "/api/v1/auth/sign-in-challenge/replace",
    "/api/v1/auth/sign-in-challenge/cancel",
    "/api/v1/account/profile",
    "/api/v1/account/password",
    "/api/v1/account/preferences",
    "/api/v1/account/links"
  })
  public ResponseEntity<?> mutate(
      @RequestBody Map<String, Object> body,
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication) {
    return accounts.forward(request, response, authentication, body);
  }
}
