package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** DLV-1015: the local sign-out's token revocation, moved line for line from SignInController.revoke. */
class SignInIdentityClientTest {
    OAuthClientDetails oauth(){return new OAuthClientDetails("http://127.0.0.1:4350","lookahead-test","synthetic-client-secret-only-for-testing","http://identity:8080","http://domain-api:8080","http://127.0.0.1:4350");}
    @Test void revokePostsTheTokenAsAFormToTheIdentityServiceWithTheClientCredentials(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        var basic=new HttpHeaders();basic.setBasicAuth(oauth.clientId(),oauth.clientSecret());
        server.expect(requestTo("http://identity:8080/oauth2/revoke")).andExpect(method(HttpMethod.POST))
            .andExpect(header("Authorization",basic.getFirst("Authorization"))).andExpect(header("Content-Type","application/x-www-form-urlencoded"))
            .andExpect(headerDoesNotExist("Cookie")).andExpect(headerDoesNotExist("X-LookAhead-Gateway-Secret"))
            .andExpect(content().string("token=synthetic%2Btoken%2F%3D"))
            .andRespond(withSuccess());
        new SignInIdentityClient(oauth,builder.build()).revoke("synthetic+token/=");server.verify();
    }
    @Test void anAnswerThatIsNotASuccessIsThrownToTheCaller(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        server.expect(requestTo(oauth.identityUpstream()+"/oauth2/revoke")).andExpect(method(HttpMethod.POST)).andRespond(withServerError());
        var client=new SignInIdentityClient(oauth,builder.build());
        assertThatExceptionOfType(RestClientException.class).isThrownBy(()->client.revoke("synthetic-token"));server.verify();
    }
}
