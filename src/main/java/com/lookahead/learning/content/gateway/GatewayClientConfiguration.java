package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import com.lookahead.learning.content.oauth.OAuthProperties;
import org.springframework.context.annotation.*;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@Configuration
@Profile("gateway")
public class GatewayClientConfiguration {
    @Bean ClientRegistrationRepository gatewayClient(OAuthSettings settings) {
        var client=ClientRegistration.withRegistrationId("lookahead")
                .clientId(settings.clientId()).clientSecret(settings.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(settings.frontend()+"/login/oauth2/code/lookahead")
                .scope("openid","profile","account","content","support")
                .authorizationUri(settings.issuer()+"/oauth2/authorize")
                .tokenUri(settings.identityUpstream()+"/oauth2/token")
                .jwkSetUri(settings.identityUpstream()+"/oauth2/jwks")
                .userInfoUri(settings.identityUpstream()+"/userinfo")
                .userNameAttributeName(IdTokenClaimNames.SUB).issuerUri(settings.issuer())
                .providerConfigurationMetadata(Map.of("end_session_endpoint",settings.issuer()+"/connect/logout"))
                .clientName("Look Ahead").build();
        return new InMemoryClientRegistrationRepository(client);
    }
    @Bean OAuth2AuthorizedClientRepository gatewayClients() { return new HttpSessionOAuth2AuthorizedClientRepository(); }
    @Bean OAuth2AuthorizedClientManager gatewayClientManager(ClientRegistrationRepository clients, OAuth2AuthorizedClientRepository authorized, OAuthProperties properties) {
        var manager=new DefaultOAuth2AuthorizedClientManager(clients,authorized);
        var refresh=new RestClientRefreshTokenTokenResponseClient();refresh.setRestClient(tokenHttp(properties));
        manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode()
                .refreshToken(configurer->configurer.accessTokenResponseClient(refresh)).build());
        return manager;
    }
    private static JdkClientHttpRequestFactory boundedRequests(OAuthProperties properties) {
        // HttpURLConnection's streaming POST handling can discard a 401 response body.
        // Preserve Identity's structured credential errors without following redirects.
        var client = java.net.http.HttpClient.newBuilder()
                .connectTimeout(properties.connectTimeout())
                .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                .build();
        var factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(properties.readTimeout());
        return factory;
    }
    @Bean RestClient gatewayHttp(OAuthProperties properties) { return RestClient.builder().requestFactory(boundedRequests(properties)).build(); }
    private static RestClient tokenHttp(OAuthProperties properties) {
        return RestClient.builder().requestFactory(boundedRequests(properties)).configureMessageConverters(converters->{
            converters.addCustomConverter(new FormHttpMessageConverter());
            converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
        }).defaultStatusHandler(new OAuth2ErrorResponseErrorHandler()).build();
    }
    @Bean JwtDecoderFactory<ClientRegistration> gatewayIdTokenDecoders(OAuthProperties properties) {
        var decoders=new java.util.concurrent.ConcurrentHashMap<String,JwtDecoder>();
        return registration->decoders.computeIfAbsent(registration.getRegistrationId(),key->{
            var decoder=NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                    .restOperations(new RestTemplate(boundedRequests(properties))).build();
            decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(new JwtTimestampValidator(),new OidcIdTokenValidator(registration)));
            return decoder;
        });
    }
    @Bean RestClientAuthorizationCodeTokenResponseClient gatewayTokenExchange(OAuthProperties properties) {
        var exchange = new RestClientAuthorizationCodeTokenResponseClient();
        exchange.setRestClient(tokenHttp(properties));
        return exchange;
    }

    @Bean OidcUserService gatewayOidcUsers(OAuthProperties properties) {
        var userInfo = new DefaultOAuth2UserService();
        var userHttp = new RestTemplate(boundedRequests(properties));
        userHttp.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
        userInfo.setRestOperations(userHttp);
        var oidcUsers = new OidcUserService();
        oidcUsers.setOauth2UserService(userInfo);
        return oidcUsers;
    }
}
