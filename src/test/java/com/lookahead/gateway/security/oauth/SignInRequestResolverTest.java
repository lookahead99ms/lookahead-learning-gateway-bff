package com.lookahead.gateway.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/** DLV-969: our sign-in page names the provider; Cognito then skips its own page. */
class SignInRequestResolverTest {
  final InMemoryClientRegistrationRepository clients =
      new InMemoryClientRegistrationRepository(
          ClientRegistration.withRegistrationId("lookahead")
              .clientId("syntheticclient1")
              .clientSecret("synthetic-secret")
              .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
              .redirectUri("https://dev.example.test/login/oauth2/code/lookahead")
              .scope("openid", "email")
              .authorizationUri(
                  "https://dev-example.auth.us-east-2.amazoncognito.com/oauth2/authorize")
              .tokenUri("https://dev-example.auth.us-east-2.amazoncognito.com/oauth2/token")
              .build());

  OAuth2AuthorizationRequest resolve(SignInRequestResolver resolver, String provider) {
    var request = new MockHttpServletRequest("GET", "/oauth2/authorization/lookahead");
    request.setServletPath("/oauth2/authorization/lookahead");
    if (provider != null) request.setParameter("provider", provider);
    return resolver.resolve(request);
  }

  @Test
  void googleGoesStraightToGoogleWithTheAccountChooser() {
    var resolver = new SignInRequestResolver(clients, true, true);
    Map<String, Object> google = resolve(resolver, "google").getAdditionalParameters();
    assertThat(google)
        .containsEntry("identity_provider", "Google")
        .containsEntry("prompt", "select_account");
    assertThat(resolve(resolver, "google").getAuthorizationRequestUri())
        .contains(
            "identity_provider=Google", "prompt=select_account", "code_challenge_method=S256");
    assertThat(resolve(resolver, "password").getAdditionalParameters())
        .containsEntry("identity_provider", "COGNITO")
        .containsEntry("prompt", "login");
    assertThat(resolve(resolver, null).getAdditionalParameters())
        .containsEntry("prompt", "login")
        .doesNotContainKey("identity_provider");
    assertThat(resolve(resolver, "Google").getAdditionalParameters())
        .doesNotContainKey("identity_provider");
    // Another path is not an authorization request at all.
    var other = new MockHttpServletRequest("GET", "/bff/login");
    other.setServletPath("/bff/login");
    assertThat(resolver.resolve(other)).isNull();
    assertThat(
            resolver
                .resolve(new MockHttpServletRequest("GET", "/x"), "lookahead")
                .getAdditionalParameters())
        .containsEntry("prompt", "login");
  }

  @Test
  void googleIsIgnoredWhileSwitchedOffAndLocalModeIgnoresProviders() {
    assertThat(
            resolve(new SignInRequestResolver(clients, true, false), "google")
                .getAdditionalParameters())
        .containsEntry("prompt", "login")
        .doesNotContainKey("identity_provider");
    var local = new SignInRequestResolver(clients, false, true);
    assertThat(resolve(local, "google").getAdditionalParameters())
        .doesNotContainKeys("identity_provider", "prompt");
    assertThat(resolve(local, "google").getAuthorizationRequestUri())
        .contains("code_challenge_method=S256");
  }
}
