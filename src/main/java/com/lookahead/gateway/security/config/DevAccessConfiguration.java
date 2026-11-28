package com.lookahead.gateway.security.config;

import com.lookahead.gateway.client.DevAccessCognitoClient;
import com.lookahead.gateway.security.filter.DevAccessFilter;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.DevAccessGate;
import java.time.Clock;
import java.time.Duration;
import org.apache.catalina.session.StandardManager;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.DefaultRetryStrategy;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

/**
 * DLV-969: the DEV gate opens on a Look Ahead pool sign-in; no second pool, client registration or
 * directory check.
 */
@Configuration
@Profile("lower-cost-dev")
public class DevAccessConfiguration {
  @Bean
  WebServerFactoryCustomizer<TomcatServletWebServerFactory> boundedDevSessions() {
    return factory ->
        factory.addContextCustomizers(context -> {
          var manager = new StandardManager();
          manager.setPathname(null);
          manager.setMaxActiveSessions(1000);
          context.setManager(manager);
        });
  }

  @Bean
  public DevAccessGate devAccessGate(Environment env) {
    return DevAccessGate.freshSignIn(
        Clock.systemUTC(), env.getRequiredProperty("app.deployment-environment"));
  }

  /**
   * The Cognito connection of the gate's five-minute question: the task role, short timeouts, no
   * SDK retries.
   */
  @Bean(destroyMethod = "")
  CognitoIdentityProviderClient devAccessCognitoIdp(OAuthClientDetails oauth) {
    String region = OAuthClientDetails.region(oauth.issuer());
    return CognitoIdentityProviderClient.builder()
        .region(Region.of(region))
        .credentialsProvider(ContainerCredentialsProvider.builder().build())
        .httpClientBuilder(
            UrlConnectionHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(2))
                .socketTimeout(Duration.ofSeconds(3)))
        .overrideConfiguration(c ->
            c.apiCallTimeout(Duration.ofSeconds(4))
                .apiCallAttemptTimeout(Duration.ofSeconds(3))
                .retryStrategy(DefaultRetryStrategy.doNotRetry()))
        .build();
  }

  @Bean
  public DevAccessCognitoClient devAccessCognitoClient(OAuthClientDetails oauth) {
    return new DevAccessCognitoClient(oauth.issuer(), devAccessCognitoIdp(oauth));
  }

  /**
   * DLV-969: every five minutes an open gate session asks the pool whether its user was disabled or
   * deleted.
   */
  @Bean
  public FilterRegistrationBean<DevAccessFilter> devAccessFilter(OAuthClientDetails oauth) {
    var bean =
        new FilterRegistrationBean<>(
            new DevAccessFilter(Clock.systemUTC(), devAccessCognitoClient(oauth)));
    bean.setOrder(-110);
    return bean;
  }

  @Bean
  @Order(0)
  SecurityFilterChain devAccessSecurity(HttpSecurity http) throws Exception {
    http.securityMatcher("/dev/**")
        .securityContext(c -> c.securityContextRepository(new NullSecurityContextRepository()))
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .requestCache(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(a -> a.anyRequest().permitAll());
    return http.build();
  }
}
