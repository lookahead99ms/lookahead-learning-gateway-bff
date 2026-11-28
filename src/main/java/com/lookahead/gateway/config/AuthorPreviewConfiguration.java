package com.lookahead.gateway.config;

import com.lookahead.gateway.client.AuthorPreviewDomainClient;
import com.lookahead.gateway.client.AuthorPreviewRequestFactory;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.proxy.AuthorPreviewProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.AuthorPreviewUpstream;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestClient;

@Configuration
@Profile("gateway")
@ConditionalOnProperty(name = "app.author-previews.enabled", havingValue = "true")
class AuthorPreviewConfiguration {
  @Bean
  AuthorPreviewUpstream authorPreviewUpstream(Environment environment, OAuthClientDetails oauth) {
    return AuthorPreviewUpstream.from(environment, oauth.frontend());
  }

  /**
   * The one connection of the author previews, used for the Domain's access check and for the
   * preview server: redirects are never followed. It is not a default candidate, so every plain
   * {@code RestClient} parameter elsewhere still receives {@code upstreamHttp}; the two beans below
   * ask for it by name.
   */
  @Bean(defaultCandidate = false)
  RestClient authorPreviewHttp(OAuthConfigValues values) {
    var requests = new AuthorPreviewRequestFactory();
    requests.setConnectTimeout(values.connectTimeout());
    requests.setReadTimeout(values.readTimeout());
    return RestClient.builder().requestFactory(requests).build();
  }

  @Bean
  AuthorPreviewDomainClient authorPreviewDomainClient(
      OAuthClientDetails oauth, @Qualifier("authorPreviewHttp") RestClient http) {
    return new AuthorPreviewDomainClient(oauth, http);
  }

  @Bean
  AuthorPreviewProxy authorPreviewProxy(
      AuthorPreviewUpstream upstream,
      AuthorPreviewDomainClient domain,
      SignInTokenClient tokens,
      @Qualifier("authorPreviewHttp") RestClient http) {
    return new AuthorPreviewProxy(upstream, domain, tokens, http);
  }
}
