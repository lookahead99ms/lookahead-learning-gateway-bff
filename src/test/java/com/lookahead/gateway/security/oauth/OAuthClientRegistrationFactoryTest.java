package com.lookahead.gateway.security.oauth;

import static org.assertj.core.api.Assertions.*;

import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

class OAuthClientRegistrationFactoryTest {
  static final String ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example",
      LOGIN = "https://example.auth.us-east-2.amazoncognito.com";

  @Test
  void localModeUsesTheIdentityServiceAndTheFiveLocalScopes() {
    var oauth =
        new OAuthClientDetails(
            "http://127.0.0.1:4300",
            "client",
            "synthetic-secret",
            "http://identity:8080",
            "http://domain-api:8080",
            "http://127.0.0.1:4300");
    var registration = OAuthClientRegistrationFactory.from(oauth);
    assertThat(registration.getRegistrationId()).isEqualTo("lookahead");
    assertThat(registration.getClientName()).isEqualTo("Look Ahead");
    assertThat(registration.getClientId()).isEqualTo("client");
    assertThat(registration.getClientSecret()).isEqualTo("synthetic-secret");
    assertThat(registration.getClientAuthenticationMethod())
        .isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    assertThat(registration.getAuthorizationGrantType())
        .isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
    assertThat(registration.getRedirectUri())
        .isEqualTo("http://127.0.0.1:4300/login/oauth2/code/lookahead");
    assertThat(registration.getScopes())
        .containsExactlyInAnyOrder("openid", "profile", "account", "content", "support");
    var provider = registration.getProviderDetails();
    assertThat(provider.getAuthorizationUri()).isEqualTo("http://127.0.0.1:4300/oauth2/authorize");
    assertThat(provider.getTokenUri()).isEqualTo("http://identity:8080/oauth2/token");
    assertThat(provider.getJwkSetUri()).isEqualTo("http://identity:8080/oauth2/jwks");
    assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo("http://identity:8080/userinfo");
    assertThat(provider.getUserInfoEndpoint().getUserNameAttributeName()).isEqualTo("sub");
    assertThat(provider.getIssuerUri()).isEqualTo("http://127.0.0.1:4300");
    assertThat(provider.getConfigurationMetadata())
        .containsOnly(entry("end_session_endpoint", "http://127.0.0.1:4300/connect/logout"));
  }

  @Test
  void cloudModeUsesCognitoAndThePrefixedScopes() {
    var oauth =
        new OAuthClientDetails(
            ISSUER,
            "client",
            "synthetic-secret",
            null,
            "https://domain.example",
            "https://dev.example",
            LOGIN,
            "lookahead",
            "synthetic-gateway-secret");
    var registration = OAuthClientRegistrationFactory.from(oauth);
    assertThat(registration.getRedirectUri())
        .isEqualTo("https://dev.example/login/oauth2/code/lookahead");
    assertThat(registration.getScopes())
        .containsExactlyInAnyOrder(
            "openid",
            "profile",
            "email",
            "aws.cognito.signin.user.admin",
            "lookahead/account",
            "lookahead/content",
            "lookahead/support");
    var provider = registration.getProviderDetails();
    assertThat(provider.getAuthorizationUri()).isEqualTo(LOGIN + "/oauth2/authorize");
    assertThat(provider.getTokenUri()).isEqualTo(LOGIN + "/oauth2/token");
    assertThat(provider.getJwkSetUri()).isEqualTo(ISSUER + "/.well-known/jwks.json");
    assertThat(provider.getUserInfoEndpoint().getUri()).isEqualTo(LOGIN + "/oauth2/userInfo");
    assertThat(provider.getIssuerUri()).isEqualTo(ISSUER);
    assertThat(provider.getConfigurationMetadata())
        .containsOnly(entry("end_session_endpoint", LOGIN + "/logout"));
  }

  @Test
  void theBeanHoldsExactlyThisRegistration() {
    var oauth =
        new OAuthClientDetails(
            ISSUER,
            "client",
            "synthetic-secret",
            null,
            "https://domain.example",
            "https://dev.example",
            LOGIN,
            "lookahead",
            "synthetic-gateway-secret");
    var held =
        new OAuthClientConfiguration()
            .oauthClientRegistrations(oauth)
            .findByRegistrationId("lookahead");
    var built = OAuthClientRegistrationFactory.from(oauth);
    assertThat(held).usingRecursiveComparison().isEqualTo(built);
  }
}
