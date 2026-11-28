package com.lookahead.gateway.security.config;

import com.lookahead.gateway.client.UpstreamHttpFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.security.oauth.OAuthIdTokenDecoderFactory;
import org.springframework.context.annotation.*;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.endpoint.*;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

// Exception, decided 2026-11-25 (DLV-1015): this class hands a transport to Spring Security's own
// callers of the provider, so those calls are made by Spring's classes and not by a client class of
// ours (rule 4: only a client class talks to an outside system). They are: the authorized-client
// manager with its refresh client (token renewal; our classes reach it only through
// client/SignInTokenClient), the token-exchange client (the code exchange at sign-in), the
// user-info service, and the ID-token decoders of security/oauth/OAuthIdTokenDecoderFactory (the
// signing keys; besides Spring Security, our own security/session/PasswordSignInSession asks them
// to check a password sign-in's ID token).
@Configuration
@Profile("gateway")
public class OAuthClientConfiguration {
  @Bean
  public ClientRegistrationRepository oauthClientRegistrations(OAuthClientDetails oauth) {
    var client = OAuthClientRegistrationFactory.from(oauth);
    return new InMemoryClientRegistrationRepository(client);
  }

  @Bean
  OAuth2AuthorizedClientRepository oauthAuthorizedClients() {
    return new HttpSessionOAuth2AuthorizedClientRepository();
  }

  @Bean
  OAuth2AuthorizedClientManager oauthAuthorizedClientManager(
      ClientRegistrationRepository clients,
      OAuth2AuthorizedClientRepository authorized,
      OAuthConfigValues values) {
    var manager = new DefaultOAuth2AuthorizedClientManager(clients, authorized);
    var refresh = new RestClientRefreshTokenTokenResponseClient();
    refresh.setRestClient(tokenHttp(values));
    manager.setAuthorizedClientProvider(
        OAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode()
            .refreshToken(configurer -> configurer.accessTokenResponseClient(refresh))
            .build());
    return manager;
  }

  private static RestClient tokenHttp(OAuthConfigValues values) {
    return RestClient.builder()
        .requestFactory(UpstreamHttpFactory.boundedRequests(values))
        .configureMessageConverters(converters -> {
          converters.addCustomConverter(new FormHttpMessageConverter());
          converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
        })
        .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
        .build();
  }

  @Bean
  JwtDecoderFactory<ClientRegistration> oauthIdTokenDecoders(OAuthConfigValues values) {
    return new OAuthIdTokenDecoderFactory(
        new RestTemplate(UpstreamHttpFactory.boundedRequests(values)));
  }

  @Bean
  RestClientAuthorizationCodeTokenResponseClient oauthTokenExchange(OAuthConfigValues values) {
    var exchange = new RestClientAuthorizationCodeTokenResponseClient();
    exchange.setRestClient(tokenHttp(values));
    return exchange;
  }

  @Bean
  OidcUserService oauthOidcUsers(OAuthConfigValues values) {
    var userInfo = new DefaultOAuth2UserService();
    var userHttp = new RestTemplate(UpstreamHttpFactory.boundedRequests(values));
    userHttp.setErrorHandler(new OAuth2ErrorResponseErrorHandler());
    userInfo.setRestOperations(userHttp);
    var oidcUsers = new OidcUserService();
    oidcUsers.setOauth2UserService(userInfo);
    return oidcUsers;
  }
}
