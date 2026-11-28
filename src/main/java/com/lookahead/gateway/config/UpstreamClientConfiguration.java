package com.lookahead.gateway.config;

import com.lookahead.gateway.client.SignInCognitoClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInIdentityClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.client.TestSessionDomainClient;
import com.lookahead.gateway.proxy.AccountCloudProxy;
import com.lookahead.gateway.proxy.AccountIdentityProxy;
import com.lookahead.gateway.proxy.AccountMergeProxy;
import com.lookahead.gateway.proxy.DevWebProxy;
import com.lookahead.gateway.proxy.DomainProxy;
import com.lookahead.gateway.proxy.IdentityProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.util.DevServiceOrigins;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestClient;

/**
 * The clients and forwarders that call our own upstreams over the one general HTTP connection (bean
 * {@code upstreamHttp}). Each is created in exactly the modes in which the class that uses it
 * exists.
 */
@Configuration
@Profile("gateway")
public class UpstreamClientConfiguration {
  @Bean
  SignInDomainClient signInDomainClient(OAuthClientDetails oauth, RestClient http) {
    return new SignInDomainClient(oauth, http);
  }

  /** Every mode, as {@code SignOutHandler}, which holds both the local and the cloud sign-out. */
  @Bean
  SignInIdentityClient signInIdentityClient(OAuthClientDetails oauth, RestClient http) {
    return new SignInIdentityClient(oauth, http);
  }

  /** Every mode, as {@code SignOutHandler}, which holds both the local and the cloud sign-out. */
  @Bean
  SignInCognitoClient signInCognitoClient(OAuthClientDetails oauth, RestClient http) {
    return new SignInCognitoClient(oauth, http);
  }

  /**
   * Every mode: the one place that asks Spring Security's authorized-client manager for a sign-in's
   * current tokens.
   */
  @Bean
  SignInTokenClient signInTokenClient(OAuth2AuthorizedClientManager manager) {
    return new SignInTokenClient(manager);
  }

  @Bean
  DomainProxy domainProxy(OAuthClientDetails oauth, SignInTokenClient tokens, RestClient http) {
    return new DomainProxy(oauth, tokens, http);
  }

  /**
   * DEV only, as {@code TestSessionHandler}, which calls it for the routes of {@code
   * TestSessionController}.
   */
  @Bean
  @ConditionalOnExpression("'${app.deployment-environment:}' == 'dev'")
  TestSessionDomainClient testSessionDomainClient(OAuthClientDetails oauth, RestClient http) {
    return new TestSessionDomainClient(oauth, http);
  }

  /** DEV and PROD, as {@code AccountMergeProxyController}. */
  @Bean
  @ConditionalOnExpression(
      "'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
  AccountMergeProxy accountMergeProxy(
      OAuthClientDetails oauth,
      SignInTokenClient tokens,
      OAuth2AuthorizedClientRepository clients,
      RestClient http) {
    return new AccountMergeProxy(oauth, tokens, clients, http);
  }

  /** DEV and PROD, as {@code AccountCloudController}. */
  @Bean
  @ConditionalOnExpression(
      "'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
  AccountCloudProxy accountCloudProxy(
      SignInTokenClient tokens,
      OAuth2AuthorizedClientRepository clients,
      SignInDomainClient sessions) {
    return new AccountCloudProxy(tokens, clients, sessions);
  }

  /**
   * Local only, as {@code IdentityProxyController}: its constructor refuses an invalid or shared
   * cookie name at start-up.
   */
  @Bean
  @ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
  IdentityProxy identityProxy(
      OAuthClientDetails oauth,
      RestClient http,
      @Value("${app.gateway.identity-cookie-name:LOOKAHEAD_SESSION}") String identityCookieName,
      @Value("${app.gateway.sign-in-binding-cookie-name:LOOKAHEAD_SIGNIN_BINDING}")
          String bindingCookie,
      @Value("${app.gateway.sign-in-challenge-cookie-name:LOOKAHEAD_SIGNIN_CHALLENGE}")
          String challengeCookie,
      @Value("${server.servlet.session.cookie.name:LOOKAHEAD_GATEWAY}") String sessionCookie) {
    return new IdentityProxy(
        oauth, http, identityCookieName, bindingCookie, challengeCookie, sessionCookie);
  }

  /**
   * Local only, as {@code AccountIdentityController}: reads the session cookie settings once, at
   * start-up.
   */
  @Bean
  @ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
  AccountIdentityProxy accountIdentityProxy(IdentityProxy identity, Environment environment) {
    return new AccountIdentityProxy(identity, environment);
  }

  /**
   * The {@code lower-cost-dev} profile only, as {@code DevWebController}: the origins bean it
   * receives refuses a wrong Web upstream at start-up.
   */
  @Bean
  @Profile("lower-cost-dev")
  DevWebProxy devWebProxy(RestClient http, DevServiceOrigins origins) {
    return new DevWebProxy(http, origins);
  }
}
