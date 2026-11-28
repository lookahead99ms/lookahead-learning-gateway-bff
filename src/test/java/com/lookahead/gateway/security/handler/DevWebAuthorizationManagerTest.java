package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * DLV-1015: the last authorization rule of the sign-in chain as a class of its own. The expression
 * moved here unchanged from the lambda in SecurityFilterChainConfiguration; the chain drives it in
 * GatewayBffApplicationLowerCostDevIntegrationTest (DEV) and
 * SecurityFilterChainConfigurationIntegrationTest (every other route is refused).
 */
class DevWebAuthorizationManagerTest {
  /** The rule never asks who is signed in. */
  static final Supplier<Authentication> NOBODY_IS_ASKED =
      () -> {
        throw new AssertionError("the rule does not look at the sign-in");
      };

  static MockEnvironment environment(String... profiles) {
    var environment = new MockEnvironment();
    environment.setActiveProfiles(profiles);
    return environment;
  }

  static boolean granted(DevWebAuthorizationManager rule, String method, String path) {
    var result =
        rule.authorize(
            NOBODY_IS_ASKED,
            new RequestAuthorizationContext(new MockHttpServletRequest(method, path)));
    assertThat(result).isExactlyInstanceOf(AuthorizationDecision.class);
    return result.isGranted();
  }

  @Test
  void inDevAReadOfAPathTheWebMayServeIsAllowedAndNothingElse() {
    var rule = new DevWebAuthorizationManager(environment("gateway", "lower-cost-dev"));
    for (String path : new String[] {"/", "/learn", "/main.js", "/sign-in", "/account/merge"}) {
      assertThat(granted(rule, "GET", path)).as("GET " + path).isTrue();
      assertThat(granted(rule, "HEAD", path)).as("HEAD " + path).isTrue();
      for (String method : new String[] {"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "get"})
        assertThat(granted(rule, method, path)).as(method + " " + path).isFalse();
    }
    for (String path :
        new String[] {
          "/bff/unknown",
          "/api/v2/anything",
          "/content",
          "/dev/access",
          "/actuator/env",
          "/oauth2/else",
          "/login",
          "/logout",
          "/a/../b",
          "/a%2Fb",
          "/a;b",
          "//outside.example",
          "/a\\b",
          "/.env",
          "/keys/server.pem",
          "/main.js.map"
        }) assertThat(granted(rule, "GET", path)).as("GET " + path).isFalse();
  }

  @Test
  void outsideDevEveryRequestThatReachesTheLastRuleIsRefused() {
    for (String[] profiles :
        new String[][] {{"gateway"}, {"gateway", "local"}, {"gateway", "prod"}, {}}) {
      var rule = new DevWebAuthorizationManager(environment(profiles));
      for (String method : new String[] {"GET", "HEAD", "POST"})
        for (String path : new String[] {"/", "/learn", "/main.js", "/bff/unknown"})
          assertThat(granted(rule, method, path))
              .as(String.join(",", profiles) + " " + method + " " + path)
              .isFalse();
    }
  }

  @Test
  void theProfileIsReadAtEachRequestNotWhenTheRuleIsBuilt() {
    var environment = environment("gateway");
    var rule = new DevWebAuthorizationManager(environment);
    assertThat(granted(rule, "GET", "/learn")).isFalse();
    environment.setActiveProfiles("gateway", "lower-cost-dev");
    assertThat(granted(rule, "GET", "/learn")).isTrue();
  }
}
