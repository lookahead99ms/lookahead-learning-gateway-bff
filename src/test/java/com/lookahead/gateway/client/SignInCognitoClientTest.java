package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * DLV-1015: the cloud sign-out's refresh-token revocation, moved line for line from
 * SignInController.cloudLogout.
 */
class SignInCognitoClientTest {
  OAuthClientDetails oauth() {
    return OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
  }

  @Test
  void revokeRefreshTokenPostsTheTokenAndItsHintAsAFormToTheManagedLoginWithTheClientCredentials() {
    var builder = RestClient.builder();
    var server = MockRestServiceServer.bindTo(builder).build();
    var oauth = oauth();
    var basic = new HttpHeaders();
    basic.setBasicAuth(oauth.clientId(), oauth.clientSecret());
    server
        .expect(requestTo("https://example.auth.us-east-2.amazoncognito.com/oauth2/revoke"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", basic.getFirst("Authorization")))
        .andExpect(header("Content-Type", "application/x-www-form-urlencoded"))
        .andExpect(headerDoesNotExist("Cookie"))
        .andExpect(headerDoesNotExist("X-LookAhead-Gateway-Secret"))
        .andExpect(content().string("token=synthetic%2Btoken%2F%3D&token_type_hint=refresh_token"))
        .andRespond(withSuccess());
    new SignInCognitoClient(oauth, builder.build()).revokeRefreshToken("synthetic+token/=");
    server.verify();
  }

  @Test
  void anAnswerThatIsNotASuccessIsThrownToTheCaller() {
    var builder = RestClient.builder();
    var server = MockRestServiceServer.bindTo(builder).build();
    var oauth = oauth();
    server
        .expect(requestTo(oauth.managedLogin() + "/oauth2/revoke"))
        .andExpect(method(HttpMethod.POST))
        .andRespond(withServerError());
    var client = new SignInCognitoClient(oauth, builder.build());
    assertThatExceptionOfType(RestClientException.class)
        .isThrownBy(() -> client.revokeRefreshToken("synthetic-token"));
    server.verify();
  }
}
