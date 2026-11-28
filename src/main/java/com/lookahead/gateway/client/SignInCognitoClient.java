package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Cognito's token revocation ({@code POST <managed login>/oauth2/revoke}), used by the cloud
 * sign-out for the refresh token.
 */
public final class SignInCognitoClient {
  private final OAuthClientDetails oauth;
  private final RestClient http;

  public SignInCognitoClient(OAuthClientDetails oauth, RestClient http) {
    this.oauth = oauth;
    this.http = http;
  }

  public void revokeRefreshToken(String token) {
    var form = new LinkedMultiValueMap<String, String>();
    form.add("token", token);
    form.add("token_type_hint", "refresh_token");
    http.post()
        .uri(oauth.managedLogin() + "/oauth2/revoke")
        .headers(h -> h.setBasicAuth(oauth.clientId(), oauth.clientSecret()))
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(form)
        .retrieve()
        .toBodilessEntity();
  }
}
