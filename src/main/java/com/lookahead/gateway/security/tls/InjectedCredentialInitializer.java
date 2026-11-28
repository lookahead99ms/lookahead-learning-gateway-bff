package com.lookahead.gateway.security.tls;

import com.lookahead.gateway.log.OpsLog;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.Profiles;

/**
 * Runs before context refresh, SSL bundle construction and any listening server. A refused start
 * logs which injected variable could not be read or was rejected (DLV-969), by name only; the
 * validator names its own rejections. What the validator accepted is published as properties ahead
 * of every other source.
 */
public final class InjectedCredentialInitializer
    implements ApplicationContextInitializer<ConfigurableApplicationContext> {
  @Override
  public void initialize(ConfigurableApplicationContext context) {
    var environment = context.getEnvironment();
    if (!environment.acceptsProfiles(Profiles.of("lower-cost-dev"))) return;
    String reading = null;
    try {
      var inputs = new LinkedHashMap<String, String>();
      for (String name :
          List.of(
              "LOOKAHEAD_TLS_SCHEMA",
              "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
              "LOOKAHEAD_TLS_SERVER_KEY",
              "LOOKAHEAD_TLS_TRUST",
              "LOOKAHEAD_TLS_SERVER_NAME",
              "LOOKAHEAD_TLS_CLIENT_CERTIFICATE",
              "LOOKAHEAD_TLS_CLIENT_KEY",
              "APP_OAUTH_CLIENT_ID",
              "LOOKAHEAD_GATEWAY_CLIENT_SECRET",
              "LOOKAHEAD_DOMAIN_GATEWAY_SECRET")) {
        reading = name;
        inputs.put(name, environment.getProperty(name));
      }
      reading = null;
      environment
          .getPropertySources()
          .addFirst(
              new MapPropertySource(
                  "validatedInjectedCredentials",
                  properties(InjectedCredentialValidator.validate(inputs))));
    } catch (Exception rejected) {
      // An unresolvable placeholder's message quotes the value; only the variable's name and the
      // type are logged.
      if (reading != null)
        throw OpsLog.startupRefused(
            "injected credential " + reading,
            rejected instanceof IllegalArgumentException
                ? "UNRESOLVED_PLACEHOLDER"
                : "UNREADABLE_" + rejected.getClass().getSimpleName(),
            InjectedCredentialValidator.REFUSED);
      throw new IllegalStateException(InjectedCredentialValidator.REFUSED);
    }
  }

  /**
   * The properties the checked credentials are published under: the two TLS bundles and the
   * secrets. Only fills the map.
   */
  static Map<String, Object> properties(InjectedCredentialValidator.Checked checked) {
    Map<String, Object> values = new LinkedHashMap<>();
    values.put("spring.ssl.bundle.pem.serving.keystore.certificate", checked.serverCertificate());
    values.put("spring.ssl.bundle.pem.serving.keystore.private-key", checked.serverKey());
    values.put("app.cognito.gateway-secret", checked.domainSecret());
    values.put("spring.ssl.bundle.pem.internal.keystore.certificate", checked.clientCertificate());
    values.put("spring.ssl.bundle.pem.internal.keystore.private-key", checked.clientKey());
    values.put("spring.ssl.bundle.pem.internal.truststore.certificate", checked.trust());
    values.put("app.oauth.client-id", checked.oauthClientId());
    values.put("app.oauth.client-secret", checked.oauthClientSecret());
    return values;
  }
}
