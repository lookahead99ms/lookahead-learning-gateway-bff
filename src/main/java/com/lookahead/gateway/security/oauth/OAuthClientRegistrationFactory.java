package com.lookahead.gateway.security.oauth;

import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

/**
 * Builds the one OAuth client registration ({@code lookahead}): Cognito's endpoints and scopes in
 * DEV and PROD, the Identity service's locally.
 */
public final class OAuthClientRegistrationFactory {
  /**
   * The id of the one registration: Spring Security keys the authorized client and the sign-in
   * token by it.
   */
  public static final String REGISTRATION_ID = "lookahead";

  private OAuthClientRegistrationFactory() {}

  public static ClientRegistration from(OAuthClientDetails oauth) {
    return ClientRegistration.withRegistrationId(REGISTRATION_ID)
        .clientId(oauth.clientId())
        .clientSecret(oauth.clientSecret())
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri(oauth.frontend() + "/login/oauth2/code/lookahead")
        .scope(
            oauth.cloud()
                ? new String[] {
                  "openid",
                  "profile",
                  "email",
                  "aws.cognito.signin.user.admin",
                  oauth.scopePrefix() + "/account",
                  oauth.scopePrefix() + "/content",
                  oauth.scopePrefix() + "/support"
                }
                : new String[] {"openid", "profile", "account", "content", "support"})
        .authorizationUri(
            (oauth.cloud() ? oauth.managedLogin() : oauth.issuer()) + "/oauth2/authorize")
        .tokenUri(
            (oauth.cloud() ? oauth.managedLogin() : oauth.identityUpstream()) + "/oauth2/token")
        .jwkSetUri(
            oauth.cloud()
                ? oauth.issuer() + "/.well-known/jwks.json"
                : oauth.identityUpstream() + "/oauth2/jwks")
        .userInfoUri(
            oauth.cloud()
                ? oauth.managedLogin() + "/oauth2/userInfo"
                : oauth.identityUpstream() + "/userinfo")
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .issuerUri(oauth.issuer())
        .providerConfigurationMetadata(
            Map.of(
                "end_session_endpoint",
                oauth.cloud()
                    ? oauth.managedLogin() + "/logout"
                    : oauth.issuer() + "/connect/logout"))
        .clientName("Look Ahead")
        .build();
  }
}
