package com.lookahead.gateway.config;

import static org.assertj.core.api.Assertions.*;

import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.proxy.DevWebProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * DLV-914 / DLV-968 S3: the connection the {@code upstreamHttp} bean method builds for the DEV
 * profile, with the bindings Domain's DEV activation contract expects (the stable Domain DNS name
 * on application mTLS 8443; Domain's loopback 8081 is readiness only, never an upstream).
 */
class UpstreamHttpConfigurationTest {
  static final String ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example";

  static final String DOMAIN = "https://domain.lookahead-dev.internal:8443";
  static final String WEB = "https://web.lookahead-dev.internal:8443";

  MockEnvironment devMutualTls() {
    var environment =
        new MockEnvironment()
            .withProperty("app.deployment-environment", "dev")
            .withProperty("app.oauth.domain-transport", "application-mtls")
            .withProperty("app.oauth.frontend", "https://dev.example.test")
            .withProperty("app.oauth.domain-api-upstream", DOMAIN)
            .withProperty("app.gateway.web-upstream", WEB)
            .withProperty("app.oauth.client-id", "syntheticlearnerclient1")
            .withProperty(
                "app.oauth.client-secret", "synthetic-learner-client-secret-never-deployed")
            .withProperty("app.cognito.issuer", ISSUER)
            .withProperty(
                "app.cognito.managed-login", "https://dev-example.auth.us-east-2.amazoncognito.com")
            .withProperty("app.cognito.scope-prefix", "lookahead-dev")
            .withProperty(
                "app.cognito.gateway-secret", "synthetic-domain-gateway-secret-never-deployed")
            .withProperty("server.ssl.enabled", "true")
            .withProperty("server.ssl.bundle", "serving");
    environment.setActiveProfiles("gateway", "lower-cost-dev");
    return environment;
  }

  @Test
  void internalClientRefusesDomainReadinessPortAndPlaintextBeforeConnecting() {
    var registry = new DefaultSslBundleRegistry();
    registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
    var environment = devMutualTls();
    var values =
        new OAuthConfigValues(
            null,
            "https://dev.example.test",
            "synthetic-learner-client-secret-never-deployed",
            "syntheticlearnerclient1",
            null,
            DOMAIN,
            Duration.ofSeconds(3),
            Duration.ofSeconds(7));
    var http =
        new UpstreamHttpConfiguration()
            .upstreamHttp(
                values,
                environment,
                provider(registry),
                provider(new UpstreamHttpConfiguration().devServiceOrigins(environment)));
    for (String rejected :
        List.of(
            "https://domain.lookahead-dev.internal:8081/actuator/health/readiness",
            "http://domain.lookahead-dev.internal:8443/api/v1/auth/me",
            "https://domain.lookahead-dev.internal/api/v1/auth/me",
            "https://web.lookahead-dev.internal:8081/index.html")) {
      assertThatThrownBy(() -> http.get().uri(URI.create(rejected)).retrieve().toBodilessEntity())
          .as(rejected)
          .satisfies(error ->
              assertThat(messages(error)).contains("Exact internal HTTPS origin required"));
    }
  }

  /**
   * DLV-1015: the two DEV upstream origins are one bean of the {@code lower-cost-dev} profile; the
   * connection and the Web forwarder receive it. A wrong upstream refuses the start with the
   * exception, message and "Startup refused" line it always had, and still only after the internal
   * TLS bundle has been read; outside DEV the settings are never read.
   */
  @Nested
  class DevOrigins {
    private final ApplicationContextRunner runner =
        new ApplicationContextRunner()
            .withUserConfiguration(
                UpstreamHttpConfiguration.class, UpstreamClientConfiguration.class)
            .withBean(
                OAuthConfigValues.class,
                () ->
                    new OAuthConfigValues(
                        null,
                        "https://dev.example.test",
                        "synthetic-learner-client-secret-never-deployed",
                        "syntheticlearnerclient1",
                        null,
                        DOMAIN,
                        Duration.ofSeconds(3),
                        Duration.ofSeconds(7)))
            .withBean(
                OAuthClientDetails.class,
                () ->
                    new OAuthClientDetails(
                        "http://127.0.0.1:4350",
                        "lookahead-test",
                        "synthetic-client-secret-only-for-testing",
                        "http://identity:8080",
                        "http://domain-api:8080",
                        "http://127.0.0.1:4350"))
            .withBean(OAuth2AuthorizedClientManager.class, () -> request -> null)
            .withBean(
                OAuth2AuthorizedClientRepository.class,
                HttpSessionOAuth2AuthorizedClientRepository::new);
    private final String[] dev = {
      "spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev"
    };

    private SslBundles internal() {
      var registry = new DefaultSslBundleRegistry();
      registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
      return registry;
    }

    @Test
    void inDevTheOriginsAreOneBeanAndTheWebForwarderReceivesIt() {
      runner
          .withBean(SslBundles.class, this::internal)
          .withPropertyValues(dev)
          .withPropertyValues(
              DevServiceOrigins.DOMAIN_PROPERTY + "=" + DOMAIN,
              DevServiceOrigins.WEB_PROPERTY + "=" + WEB)
          .run(context -> {
            assertThat(context)
                .hasNotFailed()
                .hasSingleBean(DevServiceOrigins.class)
                .hasBean("devServiceOrigins")
                .hasSingleBean(DevWebProxy.class);
            assertThat(context.getBean(DevServiceOrigins.class))
                .isEqualTo(new DevServiceOrigins(DOMAIN, WEB));
            assertThat(ReflectionTestUtils.getField(context.getBean(DevWebProxy.class), "origin"))
                .isEqualTo(WEB);
          });
    }

    @Test
    void outsideDevThereIsNoOriginsBeanAndTheTwoSettingsAreNeverRead() {
      for (String mode : new String[] {"local", "prod"})
        runner
            .withPropertyValues(
                "spring.profiles.active=gateway",
                "app.deployment-environment=" + mode,
                DevServiceOrigins.DOMAIN_PROPERTY + "=https://domain.attacker.test:8443",
                DevServiceOrigins.WEB_PROPERTY + "=https://web.attacker.test:8443")
            .run(context ->
                assertThat(context)
                    .hasNotFailed()
                    .doesNotHaveBean(DevServiceOrigins.class)
                    .doesNotHaveBean(DevWebProxy.class)
                    .hasBean("upstreamHttp"));
    }

    @Test
    void aWrongUpstreamRefusesADevStartWithTheSameExceptionMessageAndLine() {
      for (String[] wrong :
          new String[][] {
            {
              DevServiceOrigins.DOMAIN_PROPERTY + "=" + DOMAIN,
              DevServiceOrigins.WEB_PROPERTY + "=https://web.attacker.test:8443",
              "Startup refused: app.gateway.web-upstream (LOOKAHEAD_WEB_UPSTREAM, expected "
                  + WEB
                  + ")"
            },
            {
              DevServiceOrigins.DOMAIN_PROPERTY + "=https://domain.attacker.test:8443",
              DevServiceOrigins.WEB_PROPERTY + "=" + WEB,
              "Startup refused: app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM, expected "
                  + DOMAIN
                  + ")"
            },
            {
              "unset.upstreams=true",
              "unset.too=true",
              "Startup refused: app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM, expected "
                  + DOMAIN
                  + ")"
            }
          }) {
        try (var log = new LogCapture("lookahead.lifecycle")) {
          runner
              .withBean(SslBundles.class, this::internal)
              .withPropertyValues(dev)
              .withPropertyValues(wrong[0], wrong[1])
              .run(context -> {
                assertThat(context)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Explicit stable DEV Domain and Web upstreams required");
                // The connection is the first bean that asks; Spring's wrappers name it and then
                // the origins bean.
                assertThat(messages(context.getStartupFailure()))
                    .contains("Error creating bean with name 'upstreamHttp'")
                    .contains("Error creating bean with name 'devServiceOrigins'");
              });
          // Written once: the bean is created once, and the start stops there.
          assertThat(log.messages()).hasSize(1).first().asString().startsWith(wrong[2]);
        }
      }
    }

    @Test
    void aMissingInternalBundleIsStillReportedBeforeAWrongUpstream() {
      try (var log = new LogCapture("lookahead.lifecycle")) {
        runner
            .withBean(SslBundles.class, DefaultSslBundleRegistry::new)
            .withPropertyValues(dev)
            .withPropertyValues(
                DevServiceOrigins.DOMAIN_PROPERTY + "=" + DOMAIN,
                DevServiceOrigins.WEB_PROPERTY + "=https://web.attacker.test:8443")
            .run(context ->
                assertThat(context)
                    .hasFailed()
                    .getFailure()
                    .rootCause()
                    .isInstanceOf(NoSuchSslBundleException.class));
        assertThat(log.messages()).isEmpty();
      }
    }
  }

  private static <T> ObjectProvider<T> provider(T bundles) {
    return new ObjectProvider<>() {
      @Override
      public T getObject() {
        return bundles;
      }

      @Override
      public T getObject(Object... args) {
        return bundles;
      }

      @Override
      public T getIfAvailable() {
        return bundles;
      }

      @Override
      public T getIfUnique() {
        return bundles;
      }
    };
  }

  private static String messages(Throwable error) {
    var text = new StringBuilder();
    for (Throwable current = error; current != null; current = current.getCause())
      text.append(current.getMessage()).append('\n');
    return text.toString();
  }
}
