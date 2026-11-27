package com.lookahead.gateway.security.config;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import org.junit.jupiter.api.Test;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.security.oauth.OAuthIdTokenDecoderFactory;
import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import static org.assertj.core.api.Assertions.*;

class OAuthClientConfigurationTest {
    OAuthClientDetails oauth(){return OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());}
    @Test void endpointsUseCognitoAndScopesNeverTheLocalIdentity(){
        var registration=new OAuthClientConfiguration().oauthClientRegistrations(oauth()).findByRegistrationId("lookahead");
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo(oauth().managedLogin()+"/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo(oauth().managedLogin()+"/oauth2/token");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(oauth().issuer()+"/.well-known/jwks.json");
        assertThat(registration.getScopes()).contains("lookahead/account","aws.cognito.signin.user.admin");
        assertThat(oauth().identityUpstream()).isNull();
        assertThatThrownBy(()->OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production().withProperty("app.cognito.issuer",""))).isInstanceOf(IllegalStateException.class);
    }
    /**
     * DLV-1015: the ID-token decoders receive one ready transport, built with the bean (at start); it is the bounded one the
     * factory built for itself before: the JDK request factory, the configured timeouts, no redirect following.
     */
    @Test void theIdTokenDecodersReceiveTheBoundedTransportReadyMade(){
        var values=new OAuthConfigValues(oauth().issuer(),oauth().frontend(),oauth().clientSecret(),
            oauth().clientId(),null,oauth().domainApiUpstream(),Duration.ofSeconds(1),Duration.ofSeconds(2));
        var factory=new OAuthClientConfiguration().oauthIdTokenDecoders(values);
        assertThat(factory).isExactlyInstanceOf(OAuthIdTokenDecoderFactory.class);
        var transport=ReflectionTestUtils.getField(factory,"keyHttp");
        assertThat(transport).isExactlyInstanceOf(RestTemplate.class);
        var requests=((RestTemplate)transport).getRequestFactory();
        assertThat(requests).isExactlyInstanceOf(JdkClientHttpRequestFactory.class);
        var client=(HttpClient)ReflectionTestUtils.getField(requests,"httpClient");
        assertThat(client.connectTimeout()).contains(Duration.ofSeconds(1));
        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NEVER);
        assertThat(ReflectionTestUtils.getField(requests,"readTimeout")).isEqualTo(Duration.ofSeconds(2));
        assertThat(((RestTemplate)transport).getInterceptors()).isEmpty();
    }
}
