package com.lookahead.gateway.security.config;

import com.lookahead.gateway.controller.IdentityProxyController;
import com.lookahead.gateway.security.filter.SignInCheckFilter;
import com.lookahead.gateway.security.filter.SignInIdleFilter;
import com.lookahead.gateway.security.handler.DevWebAuthorizationManager;
import com.lookahead.gateway.security.handler.FramePolicyHeaderWriter;
import com.lookahead.gateway.security.handler.SignInFailureHandler;
import com.lookahead.gateway.security.handler.SignInSuccessHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.SignInProvider;
import com.lookahead.gateway.security.oauth.SignInRequestResolver;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

// Exception, decided 2026-11-25 (DLV-1015): the chain code still builds one object itself, the
// sign-in request resolver (rule 3: a configuration class only creates beans). As a bean, Spring
// Security would also hand it to the second authorization redirect filter (the one oauth2Client
// adds), which uses Spring's default resolver today, so the redirect after an
// authorization-required failure would change. Every other object of ours that the chains use
// arrives as a bean; the CSRF token repository of the second chain is Spring Security's own class,
// built in place.
@Configuration
@Profile("gateway")
public class SecurityFilterChainConfiguration {
  /**
   * Identity validates its own session and CSRF; OAuth client filters must not consume its form
   * bodies.
   */
  @Bean
  @Order(1)
  @ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
  SecurityFilterChain identityProxySecurity(HttpSecurity http, FramePolicyHeaderWriter framePolicy)
      throws Exception {
    http.securityMatcher(IdentityProxyController.PATHS)
        .csrf(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .requestCache(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
    http.headers(
        headers -> headers.frameOptions(frame -> frame.disable()).addHeaderWriter(framePolicy));
    return http.build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain signInSecurity(
      HttpSecurity http,
      ClientRegistrationRepository clients,
      OAuth2AuthorizedClientRepository authorized,
      RestClientAuthorizationCodeTokenResponseClient exchange,
      OidcUserService oidcUsers,
      SignInSuccessHandler success,
      SignInFailureHandler failure,
      SignInCheckFilter signInCheckFilter,
      Optional<SignInIdleFilter> signInIdleFilter,
      FramePolicyHeaderWriter framePolicy,
      DevWebAuthorizationManager devWeb,
      OAuthClientDetails oauth,
      Environment environment)
      throws Exception {
    http.addFilterAfter(signInCheckFilter, SecurityContextHolderFilter.class);
    if (signInIdleFilter.isPresent())
      http.addFilterBefore(signInIdleFilter.get(), SignInCheckFilter.class);
    // DLV-969: our sign-in page may name the provider (Google or password); Cognito then skips its
    // own page.
    var resolver =
        new SignInRequestResolver(
            clients, oauth.cloud(), SignInProvider.googleEnabled(environment));
    http.headers(
        headers -> headers.frameOptions(frame -> frame.disable()).addHeaderWriter(framePolicy));
    http.csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .requestCache(AbstractHttpConfigurer::disable)
        .sessionManagement(
            session -> session.sessionFixation(fixation -> fixation.changeSessionId()))
        .authorizeHttpRequests(auth ->
            auth.requestMatchers(
                    HttpMethod.GET, "/bff/api/v1/membership/plans", "/bff/api/v1/sales/active")
                .permitAll()
                // DLV-914: /actuator/info reports build.version, releaseTag and sourceRevision; GET
                // only, nothing else exposed.
                .requestMatchers(HttpMethod.GET, "/actuator/info")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/bff/api/v1/auth/password/**")
                .permitAll()
                // DLV-969 S35 (DEV only): signed out inside the open gate; the controller requires
                // the gate admission.
                .requestMatchers(HttpMethod.GET, "/bff/api/v1/auth/test-accounts")
                .permitAll()
                .requestMatchers(HttpMethod.POST, "/bff/api/v1/auth/test-session")
                .permitAll()
                .requestMatchers(
                    "/bff/login",
                    "/bff/logout/complete",
                    "/bff/api/v1/auth/csrf",
                    "/oauth2/authorization/**",
                    "/login/oauth2/code/**",
                    "/content/**",
                    "/actuator/health",
                    "/actuator/health/**",
                    "/api/v1/auth/options",
                    "/api/v1/auth/csrf")
                .permitAll()
                .requestMatchers(HttpMethod.GET, "/bff/author/previews/**")
                .authenticated()
                .requestMatchers(HttpMethod.HEAD, "/bff/author/previews/**")
                .authenticated()
                .requestMatchers(
                    "/bff/api/v1/**", "/api/v1/account/**", "/api/v1/auth/sign-in-challenge/**")
                .authenticated()
                .anyRequest()
                .access(devWeb))
        .exceptionHandling(errors ->
            errors
                .authenticationEntryPoint(failure::authenticationRequired)
                .accessDeniedHandler(failure::accessDenied))
        .oauth2Login(login ->
            login
                .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver))
                .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(exchange))
                .userInfoEndpoint(endpoint -> endpoint.oidcUserService(oidcUsers))
                .authorizedClientRepository(authorized)
                .successHandler(success::loginSucceeded)
                .failureHandler(failure::loginFailed))
        .oauth2Client(client -> client.authorizedClientRepository(authorized));
    return http.build();
  }
}
