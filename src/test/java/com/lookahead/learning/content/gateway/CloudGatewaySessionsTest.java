package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import com.lookahead.learning.content.oauth.OAuthProperties;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.http.MediaType;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class CloudGatewaySessionsTest {
    OAuthSettings settings(){return OAuthSettings.from(new GatewayDeploymentTest().production());}
    @Test void endpointsUseCognitoAndScopesNeverTheLocalIdentity(){
        var registration=new GatewayClientConfiguration().gatewayClient(settings()).findByRegistrationId("lookahead");
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(settings().managedLogin()+"/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(settings().managedLogin()+"/oauth2/token");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(settings().issuer()+"/.well-known/jwks.json");
        assertThat(registration.getScopes()).contains("lookahead/account","aws.cognito.signin.user.admin");
        assertThat(settings().identityUpstream()).isNull();
        assertThatThrownBy(()->OAuthSettings.from(new GatewayDeploymentTest().production().withProperty("app.cognito.issuer",""))).isInstanceOf(IllegalStateException.class);
    }
    @Test void browserCannotChooseSessionProofAndChallengeStaysServerSide(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var settings=settings();
        var request=new MockHttpServletRequest();request.addHeader("X-LookAhead-SignIn-Proof","attacker");request.addHeader("X-LookAhead-Gateway-Secret","attacker");
        String proof=CloudGatewaySessions.proof(request,true);assertThat(proof).hasSize(43);assertThat(CloudGatewaySessions.proof(request,true)).isEqualTo(proof);
        request.getSession().setAttribute(CloudGatewaySessions.CHALLENGE,"c".repeat(43));
        server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/replace"))
            .andExpect(header("Authorization","Bearer synthetic-token")).andExpect(header("X-LookAhead-SignIn-Proof",proof))
            .andExpect(header("X-LookAhead-Gateway-Secret",settings.gatewaySecret())).andExpect(header("X-LookAhead-Challenge","c".repeat(43)))
            .andRespond(withSuccess("{\"data\":{\"accountId\":\"synthetic-owner\"}}",MediaType.APPLICATION_JSON));
        var result=new CloudGatewaySessions(settings,builder.build()).call("replace","synthetic-token",request,java.util.Map.of("signInId","synthetic-selected"));
        assertThat(result.status()).isEqualTo(200);server.verify();
        assertThat(CloudGatewaySessions.proof(new MockHttpServletRequest(),false)).isNull();
    }
    @Test void invalidRefreshGrantExpiresAccountSessionButProviderOutagePreservesIt(){
        for(String code:java.util.List.of("invalid_grant","temporarily_unavailable")){
            var request=new MockHttpServletRequest("GET","/api/v1/account/profile");var session=new MockHttpSession();request.setSession(session);
            var response=new MockHttpServletResponse();
            var authentication=org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated("synthetic-owner","",java.util.List.of());
            org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager manager=authorization->{throw new org.springframework.security.oauth2.core.OAuth2AuthorizationException(new org.springframework.security.oauth2.core.OAuth2Error(code,"private-provider-detail",null));};
            var controller=new CloudAccountController(settings(),manager,new org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository(),RestClient.create());
            var result=controller.read(request,response,authentication);
            assertThat(result.getStatusCode().value()).isEqualTo(code.equals("invalid_grant")?401:503);
            assertThat(session.isInvalid()).isEqualTo(code.equals("invalid_grant"));
            assertThat(result.getBody().toString()).doesNotContain("private-provider-detail");
        }
    }
}
