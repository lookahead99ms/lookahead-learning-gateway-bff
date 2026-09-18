package com.lookahead.learning.content.oauth;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import java.time.Duration;

/** Gateway credentials and fixed service origins; no signing key or database settings. */
@ConfigurationProperties("app.oauth")
public record OAuthProperties(String issuer, String frontend, String clientSecret, String clientId,
        String identityUpstream, String platformUpstream,
        @DefaultValue("3s") Duration connectTimeout, @DefaultValue("7s") Duration readTimeout) {
    public OAuthProperties {
        bounded(connectTimeout, Duration.ofSeconds(10));
        bounded(readTimeout, Duration.ofSeconds(30));
    }
    private static void bounded(Duration value, Duration maximum) {
        if (value == null || value.compareTo(Duration.ofMillis(100)) < 0 || value.compareTo(maximum) > 0)
            throw new IllegalStateException("Gateway HTTP timeout outside supported range");
    }
    @Override public String toString() { return "OAuthProperties[redacted]"; }
}
