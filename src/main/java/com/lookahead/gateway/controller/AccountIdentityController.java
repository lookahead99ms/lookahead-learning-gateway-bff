package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.AccountIdentityProxy;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/** Identity authenticates these self-only operations using its own session and CSRF token. */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
public class AccountIdentityController {
  private final AccountIdentityProxy accounts;

  public AccountIdentityController(AccountIdentityProxy accounts) {
    this.accounts = accounts;
  }

  @RequestMapping(
      value = "/api/v1/account/profile",
      method = {RequestMethod.GET, RequestMethod.POST})
  public ResponseEntity<byte[]> profile(HttpServletRequest request) throws IOException {
    return accounts.profile(request);
  }

  /**
   * DLV-932: theme preference and public profile links; Identity validates session, CSRF and body.
   */
  @PostMapping({"/api/v1/account/preferences", "/api/v1/account/links"})
  public ResponseEntity<byte[]> preferences(HttpServletRequest request) throws IOException {
    return accounts.forward(request);
  }

  @PostMapping("/api/v1/account/password")
  public ResponseEntity<byte[]> password(HttpServletRequest request) throws IOException {
    return accounts.password(request);
  }

  @GetMapping({"/api/v1/account/sign-ins", "/api/v1/auth/sign-in-challenge"})
  public ResponseEntity<byte[]> signIns(HttpServletRequest request) throws IOException {
    return accounts.signIns(request);
  }

  @PostMapping({
    "/api/v1/account/sign-ins/revoke",
    "/api/v1/account/sign-ins/revoke-others",
    "/api/v1/account/sign-ins/label",
    "/api/v1/auth/sign-in-challenge/replace",
    "/api/v1/auth/sign-in-challenge/cancel"
  })
  public ResponseEntity<byte[]> updateSignIns(HttpServletRequest request) throws IOException {
    return accounts.updateSignIns(request);
  }
}
