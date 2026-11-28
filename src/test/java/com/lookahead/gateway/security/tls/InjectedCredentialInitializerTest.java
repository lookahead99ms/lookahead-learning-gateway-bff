package com.lookahead.gateway.security.tls;

import static org.junit.jupiter.api.Assertions.*;

import com.lookahead.gateway.log.LogCapture;
import java.security.InvalidAlgorithmParameterException;
import java.security.SignatureException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;

class InjectedCredentialInitializerTest extends InjectedCredentialFixture {
  @Test
  void positiveBundlesAreConsumedBySpringWithoutFiles() throws Exception {
    var properties =
        InjectedCredentialInitializer.properties(InjectedCredentialValidator.validate(input()));
    new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(SslAutoConfiguration.class))
        .withInitializer(c ->
            c.getEnvironment()
                .getPropertySources()
                .addFirst(new MapPropertySource("synthetic", properties)))
        .run(c -> {
          assertNull(c.getStartupFailure());
          var bundles = c.getBean(SslBundles.class);
          assertNotNull(bundles.getBundle("serving").createSslContext());
          assertNotNull(bundles.getBundle("internal").createSslContext());
        });
  }

  @Test
  void initializerRunsOnlyOnCloudProfileAndOverridesUnvalidatedConfiguration() throws Exception {
    try (var context = new GenericApplicationContext()) {
      var initializer = new InjectedCredentialInitializer();
      initializer.initialize(context);
      assertFalse(
          context.getEnvironment().getPropertySources().contains("validatedInjectedCredentials"));
      context.getEnvironment().setActiveProfiles("lower-cost-dev");
      var values = new HashMap<String, Object>(input());
      values.put("spring.ssl.bundle.pem.serving.keystore.private-key", "invalid override");
      context
          .getEnvironment()
          .getPropertySources()
          .addFirst(new MapPropertySource("synthetic", values));
      initializer.initialize(context);
      assertEquals(
          text("server.key"),
          context
              .getEnvironment()
              .getProperty("spring.ssl.bundle.pem.serving.keystore.private-key"));
    }
    assertTrue(
        new String(getClass().getResourceAsStream("/META-INF/spring.factories").readAllBytes())
            .contains(InjectedCredentialInitializer.class.getName()));
  }

  @Test
  void unresolvedEnvironmentPlaceholdersDoNotLeakFromStartup() {
    try (var context = new GenericApplicationContext()) {
      context.getEnvironment().setActiveProfiles("lower-cost-dev");
      context
          .getEnvironment()
          .getPropertySources()
          .addFirst(
              new MapPropertySource(
                  "synthetic", Map.of("LOOKAHEAD_TLS_SCHEMA", "${private-marker}")));
      var failure =
          assertThrows(
              IllegalStateException.class,
              () -> new InjectedCredentialInitializer().initialize(context));
      assertEquals(
          "Injected credential validation failed; application startup denied",
          failure.getMessage());
      assertNull(failure.getCause());
    }
  }

  /**
   * DLV-1015: the published properties, their order and their values, as they were before the
   * builder became its own step.
   */
  @Test
  void thePublishedPropertiesAreTheCheckedInputsInTheirOrder() throws Exception {
    var properties =
        InjectedCredentialInitializer.properties(InjectedCredentialValidator.validate(input()));
    assertEquals(
        List.of(
            "spring.ssl.bundle.pem.serving.keystore.certificate",
            "spring.ssl.bundle.pem.serving.keystore.private-key",
            "app.cognito.gateway-secret",
            "spring.ssl.bundle.pem.internal.keystore.certificate",
            "spring.ssl.bundle.pem.internal.keystore.private-key",
            "spring.ssl.bundle.pem.internal.truststore.certificate",
            "app.oauth.client-id",
            "app.oauth.client-secret"),
        new ArrayList<>(properties.keySet()));
    assertEquals(
        List.of(
            text("server.pem"),
            text("server.key"),
            "synthetic-gateway-secret",
            text("client.pem"),
            text("client.key"),
            text("ca.pem"),
            "SyntheticClient1",
            "synthetic-oauth-secret"),
        new ArrayList<>(properties.values()));
  }

  // ----- DLV-1015 (owner, 2026-11-26): the start no longer asks for the two admission values -----

  /**
   * The published source of one start in the DEV profile; {@code extra} is added to the fixture's
   * inputs.
   */
  Map<String, Object> published(Map<String, String> extra, GenericApplicationContext context)
      throws Exception {
    context.getEnvironment().setActiveProfiles("lower-cost-dev");
    var values = new HashMap<String, Object>(input());
    values.putAll(extra);
    context
        .getEnvironment()
        .getPropertySources()
        .addFirst(new MapPropertySource("synthetic", values));
    new InjectedCredentialInitializer().initialize(context);
    return ((MapPropertySource)
            context.getEnvironment().getPropertySources().get("validatedInjectedCredentials"))
        .getSource();
  }

  @Test
  void aStartWithoutTheAdmissionValuesIsAcceptedAndPublishesNoAdmissionProperty() throws Exception {
    try (var log = new LogCapture("lookahead.lifecycle");
        var context = new GenericApplicationContext()) {
      assertFalse(input().keySet().stream().anyMatch(key -> key.contains("ADMISSION")));
      var published = published(Map.of(), context);
      assertEquals(
          InjectedCredentialInitializer.properties(InjectedCredentialValidator.validate(input())),
          published);
      assertEquals(8, published.size());
      assertFalse(published.keySet().stream().anyMatch(key -> key.startsWith("app.admission")));
      for (String property : List.of("app.admission.client-id", "app.admission.client-secret")) {
        assertFalse(context.getEnvironment().containsProperty(property), property);
        assertNull(context.getEnvironment().getProperty(property), property);
      }
      assertEquals(0, log.lines().size());
    }
  }

  @Test
  void suppliedAdmissionValuesAreIgnoredByTheStart() throws Exception {
    Map<String, Object> without;
    try (var context = new GenericApplicationContext()) {
      without = published(Map.of(), context);
    }
    // Well formed, malformed, and a placeholder that cannot be resolved (which refuses the start
    // for a variable that is read).
    for (var admission :
        List.of(
            admission(),
            Map.of(
                "LOOKAHEAD_ADMISSION_CLIENT_ID",
                "invalid-id",
                "LOOKAHEAD_ADMISSION_CLIENT_SECRET",
                "short"),
            Map.of(
                "LOOKAHEAD_ADMISSION_CLIENT_ID",
                "${private-marker}",
                "LOOKAHEAD_ADMISSION_CLIENT_SECRET",
                "${private-marker}"))) {
      try (var log = new LogCapture("lookahead.lifecycle");
          var context = new GenericApplicationContext()) {
        var published = published(admission, context);
        assertEquals(without, published, admission.keySet().toString());
        assertEquals(new ArrayList<>(without.keySet()), new ArrayList<>(published.keySet()));
        assertFalse(published.keySet().stream().anyMatch(key -> key.startsWith("app.admission")));
        assertFalse(context.getEnvironment().containsProperty("app.admission.client-id"));
        assertFalse(context.getEnvironment().containsProperty("app.admission.client-secret"));
        assertEquals(0, log.lines().size());
      }
    }
  }

  @Test
  void anUnreadableVariableIsNamedWithoutItsValue() {
    try (var log = new LogCapture("lookahead.lifecycle");
        var context = new GenericApplicationContext()) {
      context.getEnvironment().setActiveProfiles("lower-cost-dev");
      context
          .getEnvironment()
          .getPropertySources()
          .addFirst(
              new MapPropertySource(
                  "synthetic", Map.of("LOOKAHEAD_TLS_TRUST", "${private-marker}")));
      var failure =
          assertThrows(
              IllegalStateException.class,
              () -> new InjectedCredentialInitializer().initialize(context));
      assertEquals(
          "Injected credential validation failed; application startup denied",
          failure.getMessage());
      assertTrue(
          LogCapture.pairs(log.last())
              .containsAll(
                  List.of(
                      "setting=injected credential LOOKAHEAD_TLS_TRUST",
                      "reason=UNRESOLVED_PLACEHOLDER")));
      log.assertNothing("private-marker");
    }
    assertEquals(
        "InvalidAlgorithmParameterException",
        InjectedCredentialValidator.reason(new InvalidAlgorithmParameterException()));
    assertEquals(
        "CHAIN_NOT_TRUSTED", InjectedCredentialValidator.reason(new CertPathBuilderException()));
    assertEquals(
        "KEY_DOES_NOT_MATCH_CERTIFICATE",
        InjectedCredentialValidator.reason(new SignatureException()));
    assertEquals(
        "CERTIFICATE_UNREADABLE", InjectedCredentialValidator.reason(new CertificateException()));
  }
}
