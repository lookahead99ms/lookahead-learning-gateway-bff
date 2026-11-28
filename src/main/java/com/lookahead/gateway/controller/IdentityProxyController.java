package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.IdentityProxy;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** Public Identity routes only. Identity owns its session, CSRF checks and authentication. */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
public class IdentityProxyController {
  public static final String[] PATHS = {
    "/api/v1/auth/options",
    "/api/v1/auth/csrf",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/continue",
    "/api/v1/auth/logout",
    "/api/v1/account/profile",
    "/api/v1/account/preferences",
    "/api/v1/account/links",
    "/api/v1/account/password",
    "/api/v1/account/sign-ins",
    "/api/v1/account/sign-ins/revoke",
    "/api/v1/account/sign-ins/revoke-others",
    "/api/v1/account/sign-ins/label",
    "/api/v1/auth/sign-in-challenge",
    "/api/v1/auth/sign-in-challenge/replace",
    "/api/v1/auth/sign-in-challenge/cancel",
    "/oauth2/authorize",
    "/oauth2/token",
    "/oauth2/jwks",
    "/oauth2/revoke",
    "/oauth2/introspect",
    "/connect/logout",
    "/userinfo",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server"
  };
  static final int MAX_BYTES = 1024 * 1024;
  private final IdentityProxy proxy;

  public IdentityProxyController(IdentityProxy proxy) {
    this.proxy = proxy;
  }

  @RequestMapping(
      value = {
        "/api/v1/auth/options",
        "/api/v1/auth/csrf",
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/continue",
        "/api/v1/auth/logout",
        "/oauth2/authorize",
        "/oauth2/token",
        "/oauth2/jwks",
        "/oauth2/revoke",
        "/oauth2/introspect",
        "/connect/logout",
        "/userinfo",
        "/.well-known/openid-configuration",
        "/.well-known/oauth-authorization-server"
      },
      method = {RequestMethod.GET, RequestMethod.POST})
  public ResponseEntity<byte[]> identity(HttpServletRequest request) throws IOException {
    return proxy.forward(request, MAX_BYTES);
  }
}
