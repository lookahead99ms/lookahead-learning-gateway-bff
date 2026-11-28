package com.lookahead.gateway.security.config;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

@Configuration
@Profile("oauth-server | gateway")
@EnableConfigurationProperties(OAuthConfigValues.class)
public class OAuthConfiguration {
  // Exception, decided 2026-11-25 (DLV-1015): the body does not read the OAuthConfigValues
  // parameter (rule 7: an unused parameter). It stays so that Spring binds and checks app.oauth
  // (the two timeouts) before the factory reads app.oauth again: measured, without it a wrong
  // timeout is refused by the factory's own bind instead of by the OAuthConfigValues bean, and the
  // exception chain of that refusal changes (its root cause stays the same). The "oauth-server"
  // half of the profile above stays as well: with "gateway" alone, a start built by hand with
  // oauth-server and without gateway would come up as an empty shell (local or PROD settings) where
  // the factory refuses it today.
  @Bean
  OAuthClientDetails oauthClientDetails(OAuthConfigValues values, Environment environment) {
    return OAuthClientDetailsFactory.from(environment);
  }
}
