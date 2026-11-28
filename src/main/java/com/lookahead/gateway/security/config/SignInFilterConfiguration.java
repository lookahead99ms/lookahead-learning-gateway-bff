package com.lookahead.gateway.security.config;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.security.filter.SignInCheckFilter;
import com.lookahead.gateway.security.filter.SignInIdleFilter;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import java.time.Clock;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * The two filters of ours that run inside the sign-in security chain ({@code
 * SecurityFilterChainConfiguration} places them). Spring Boot would also register every filter bean
 * with the servlet container, for every request and outside the security chain; each filter
 * therefore has a registration that is switched off, so it runs once, in the chain only.
 */
@Configuration
@Profile("gateway")
public class SignInFilterConfiguration {
  /**
   * Every mode: asks the Domain whether the sign-in of a private BFF request is still valid; on the
   * system clock.
   */
  @Bean
  SignInCheckFilter signInCheckFilter(
      SignInTokenClient tokens, SignInDomainClient signInDomainClient, OAuthClientDetails oauth) {
    return new SignInCheckFilter(tokens, signInDomainClient, oauth);
  }

  @Bean
  FilterRegistrationBean<SignInCheckFilter> signInCheckFilterRegistration(
      SignInCheckFilter signInCheckFilter) {
    var registration = new FilterRegistrationBean<>(signInCheckFilter);
    registration.setEnabled(false);
    return registration;
  }

  /**
   * The {@code lower-cost-dev} profile only: ends a learner sign-in after 30 idle minutes; on the
   * system clock.
   */
  @Bean
  @Profile("lower-cost-dev")
  SignInIdleFilter signInIdleFilter() {
    return new SignInIdleFilter(Clock.systemUTC());
  }

  @Bean
  @Profile("lower-cost-dev")
  FilterRegistrationBean<SignInIdleFilter> signInIdleFilterRegistration(
      SignInIdleFilter signInIdleFilter) {
    var registration = new FilterRegistrationBean<>(signInIdleFilter);
    registration.setEnabled(false);
    return registration;
  }
}
