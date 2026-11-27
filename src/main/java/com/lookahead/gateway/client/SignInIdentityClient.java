package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.client.RestClient;

/** The Identity service's token revocation ({@code POST /oauth2/revoke}), used by the local sign-out for the access and the refresh token. */
public final class SignInIdentityClient {
    private final OAuthClientDetails oauth;
    private final RestClient http;
    public SignInIdentityClient(OAuthClientDetails oauth,RestClient http){this.oauth=oauth;this.http=http;}
    public void revoke(String token) {
        var form=new LinkedMultiValueMap<String,String>();form.add("token",token);
        http.post().uri(oauth.identityUpstream()+"/oauth2/revoke").headers(headers->headers.setBasicAuth(oauth.clientId(),oauth.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().toBodilessEntity();
    }
}
