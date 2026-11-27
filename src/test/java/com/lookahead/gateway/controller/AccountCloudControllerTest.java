package com.lookahead.gateway.controller;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.proxy.AccountCloudProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.web.client.RestClient;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import static org.assertj.core.api.Assertions.*;

class AccountCloudControllerTest {
    OAuthClientDetails oauth(){return OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());}
    @Test void invalidRefreshGrantExpiresAccountSessionButProviderOutagePreservesIt(){
        for(String code:List.of("invalid_grant","temporarily_unavailable")){
            var request=new MockHttpServletRequest("GET","/api/v1/account/profile");var session=new MockHttpSession();request.setSession(session);
            var response=new MockHttpServletResponse();
            var authentication=UsernamePasswordAuthenticationToken.authenticated("synthetic-owner","",List.of());
            OAuth2AuthorizedClientManager manager=authorization->{throw new OAuth2AuthorizationException(new OAuth2Error(code,"private-provider-detail",null));};
            var controller=new AccountCloudController(new AccountCloudProxy(new SignInTokenClient(manager),new HttpSessionOAuth2AuthorizedClientRepository(),new SignInDomainClient(oauth(),RestClient.create())));
            var result=controller.read(request,response,authentication);
            assertThat(result.getStatusCode().value()).isEqualTo(code.equals("invalid_grant")?401:503);
            assertThat(session.isInvalid()).isEqualTo(code.equals("invalid_grant"));
            assertThat(result.getBody().toString()).doesNotContain("private-provider-detail");
        }
    }
}
