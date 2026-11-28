package com.lookahead.gateway.security.oauth;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Gateway BFF credentials and fixed service origins; no signing key or database settings. */
@ConfigurationProperties("app.oauth")
public record OAuthConfigValues(
    String issuer,
    String frontend,
    String clientSecret,
    String clientId,
    String identityUpstream,
    String domainApiUpstream,
    @DefaultValue("3s") Duration connectTimeout,
    @DefaultValue("7s") Duration readTimeout) {
  public OAuthConfigValues {
    bounded(connectTimeout, Duration.ofSeconds(10));
    bounded(readTimeout, Duration.ofSeconds(30));
  }

  private static void bounded(Duration value, Duration maximum) {
    if (value == null
        || value.compareTo(Duration.ofMillis(100)) < 0
        || value.compareTo(maximum) > 0)
      throw new IllegalStateException("Gateway HTTP timeout outside supported range");
  }

  @Override
  public String toString() {
    return "OAuthConfigValues[redacted]";
  }
}
