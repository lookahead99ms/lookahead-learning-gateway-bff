package com.lookahead.gateway.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** DLV-969: which sign-in provider a request may name, and the deployment switch for Google. */
class SignInProviderTest {
  @Test
  void switchReadsTheDeploymentSetting() {
    assertThat(SignInProvider.googleEnabled(new MockEnvironment())).isFalse();
    assertThat(
            SignInProvider.googleEnabled(
                new MockEnvironment().withProperty("app.cognito.google-sign-in", "true")))
        .isTrue();
    assertThat(SignInProvider.from("password", false)).contains(SignInProvider.PASSWORD);
    assertThat(SignInProvider.from("google", false)).isEmpty();
    assertThat(SignInProvider.from(null, true)).isEmpty();
  }
}
