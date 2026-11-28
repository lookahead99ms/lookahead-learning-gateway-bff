package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.AccountMergeProxy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DLV-969 S36: the person's own merge of accounts that share their verified email. The Web calls
 * these same-origin; the Gateway BFF relays them to the Domain's account routes with the
 * server-held token and sign-in proof, and passes the Domain's status and body through unchanged
 * (202, 200, 400, 404, 409, 422). Sign-in and CSRF are enforced by {@code
 * SecurityFilterChainConfiguration} ({@code /api/v1/account/**} is authenticated; every POST needs
 * the session token).
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression(
    "'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
@RequestMapping("/api/v1/account/merge")
public class AccountMergeProxyController {
  private final AccountMergeProxy proxy;

  public AccountMergeProxyController(AccountMergeProxy proxy) {
    this.proxy = proxy;
  }

  @PostMapping("/request")
  public ResponseEntity<?> request(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    return proxy.forward(HttpMethod.POST, "/request", request, response, authentication);
  }

  @GetMapping("/{token}")
  public ResponseEntity<?> candidates(
      @PathVariable String token,
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication)
      throws IOException {
    return proxy.forwardWithToken(HttpMethod.GET, token, request, response, authentication);
  }

  @PostMapping("/{token}")
  public ResponseEntity<?> merge(
      @PathVariable String token,
      HttpServletRequest request,
      HttpServletResponse response,
      Authentication authentication)
      throws IOException {
    return proxy.forwardWithToken(HttpMethod.POST, token, request, response, authentication);
  }
}
