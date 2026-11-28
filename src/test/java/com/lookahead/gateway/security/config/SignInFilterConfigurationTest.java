package com.lookahead.gateway.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.security.filter.SignInCheckFilter;
import com.lookahead.gateway.security.filter.SignInIdleFilter;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import jakarta.servlet.ServletContext;
import java.util.ArrayList;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.servlet.AbstractFilterRegistrationBean;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.boot.web.servlet.ServletContextInitializerBeans;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

/**
 * DLV-1015: the two filters of the sign-in chain are beans, and each has a registration that is
 * switched off, so the servlet container never applies them a second time outside the security
 * chain. Where the chain places them is checked with the started application
 * (GatewayBffApplicationLowerCostDevIntegrationTest,
 * SecurityFilterChainConfigurationIntegrationTest).
 */
class SignInFilterConfigurationTest {
  private static final OAuthClientDetails OAUTH =
      new OAuthClientDetails(
          "http://127.0.0.1:4350",
          "lookahead-test",
          "synthetic-client-secret-only-for-testing",
          "http://identity:8080",
          "http://domain-api:8080",
          "http://127.0.0.1:4350");
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(SignInFilterConfiguration.class)
          .withBean(OAuthClientDetails.class, () -> OAUTH)
          .withBean(SignInTokenClient.class, () -> new SignInTokenClient(request -> null))
          .withBean(
              SignInDomainClient.class, () -> new SignInDomainClient(OAUTH, RestClient.create()));

  @Test
  void theCheckFilterIsABeanInEveryModeAndItsRegistrationIsSwitchedOff() {
    for (String[] mode :
        new String[][] {
          {"spring.profiles.active=gateway,local", "app.deployment-environment=local"},
          {"spring.profiles.active=gateway", "unset.deployment-environment=true"},
          {"spring.profiles.active=gateway", "app.deployment-environment=prod"}
        }) {
      runner
          .withPropertyValues(mode)
          .run(context -> {
            assertThat(context)
                .hasNotFailed()
                .hasSingleBean(SignInCheckFilter.class)
                .hasBean("signInCheckFilter")
                .hasSingleBean(FilterRegistrationBean.class)
                .hasBean("signInCheckFilterRegistration")
                .doesNotHaveBean(SignInIdleFilter.class)
                .doesNotHaveBean("signInIdleFilterRegistration");
            var filter = context.getBean(SignInCheckFilter.class);
            var registration =
                context.getBean("signInCheckFilterRegistration", FilterRegistrationBean.class);
            assertThat(registration.isEnabled()).isFalse();
            assertThat(registration.getFilter()).isSameAs(filter);
            // The filter received the beans; it builds no client of its own.
            assertThat(ReflectionTestUtils.getField(filter, "tokens"))
                .isSameAs(context.getBean(SignInTokenClient.class));
            assertThat(ReflectionTestUtils.getField(filter, "domainClient"))
                .isSameAs(context.getBean(SignInDomainClient.class));
            assertThat(ReflectionTestUtils.getField(filter, "oauth")).isSameAs(OAUTH);
          });
    }
  }

  @Test
  void theIdleFilterAndItsSwitchedOffRegistrationExistOnlyUnderTheDevProfile() {
    runner
        .withPropertyValues(
            "spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev")
        .run(context -> {
          assertThat(context)
              .hasNotFailed()
              .hasSingleBean(SignInCheckFilter.class)
              .hasSingleBean(SignInIdleFilter.class)
              .hasBean("signInIdleFilter")
              .hasBean("signInCheckFilterRegistration")
              .hasBean("signInIdleFilterRegistration");
          assertThat(context.getBeansOfType(FilterRegistrationBean.class)).hasSize(2);
          var check =
              context.getBean("signInCheckFilterRegistration", FilterRegistrationBean.class);
          var idle = context.getBean("signInIdleFilterRegistration", FilterRegistrationBean.class);
          assertThat(check.isEnabled()).isFalse();
          assertThat(idle.isEnabled()).isFalse();
          assertThat(check.getFilter()).isSameAs(context.getBean(SignInCheckFilter.class));
          assertThat(idle.getFilter()).isSameAs(context.getBean(SignInIdleFilter.class));
        });
  }

  @Test
  void springBootAddsNoOtherRegistrationForEitherFilterAndASwitchedOffOneAddsNothing() {
    runner
        .withPropertyValues(
            "spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev")
        .run(context -> {
          // The list the web server context builds and applies: a filter bean without a
          // registration bean would appear here as a second, enabled registration made by Spring
          // Boot itself.
          var ours = new ArrayList<AbstractFilterRegistrationBean<?>>();
          for (ServletContextInitializer initializer :
              new ServletContextInitializerBeans(context.getBeanFactory()))
            if (initializer instanceof AbstractFilterRegistrationBean<?> registration
                && (registration.getFilter() instanceof SignInCheckFilter
                    || registration.getFilter() instanceof SignInIdleFilter))
              ours.add(registration);
          assertThat(ours)
              .hasSize(2)
              .allSatisfy(registration -> assertThat(registration.isEnabled()).isFalse());
          assertThat(ours)
              .containsExactlyInAnyOrder(
                  context.getBean("signInCheckFilterRegistration", FilterRegistrationBean.class),
                  context.getBean("signInIdleFilterRegistration", FilterRegistrationBean.class));
          var container = mock(ServletContext.class);
          for (var registration : ours) registration.onStartup(container);
          verifyNoInteractions(container);
        });
  }

  @Test
  void outsideTheGatewayProfileThereIsNoFilterAndNoRegistration() {
    runner
        .withPropertyValues(
            "spring.profiles.active=accounts,lower-cost-dev", "app.deployment-environment=local")
        .run(context ->
            assertThat(context)
                .hasNotFailed()
                .doesNotHaveBean(SignInCheckFilter.class)
                .doesNotHaveBean(SignInIdleFilter.class)
                .doesNotHaveBean(FilterRegistrationBean.class));
  }
}
