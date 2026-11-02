package com.lookahead.learning.content.oauth;

import java.net.URI;
import java.util.Set;
import org.springframework.core.env.Environment;

/**
 * The two private DEV upstreams, one service per application (DLV-968 S3). Deployment configuration names them
 * explicitly; the application accepts exactly the stable names, so a mistyped or hostile upstream never receives
 * the internal client certificate and the TLS hostname check always runs against a name the injected trust issued.
 */
public record DevServiceOrigins(String domain, String web) {
    public static final String DOMAIN = "https://domain.lookahead-dev.internal:8443";
    public static final String WEB = "https://web.lookahead-dev.internal:8443";
    public static final String DOMAIN_PROPERTY = "app.oauth.domain-api-upstream";
    public static final String WEB_PROPERTY = "app.gateway.web-upstream";
    // DLV-968 S3, 2026-11-01: the retired blue/green slot names stay accepted only while the old slot services
    // and their DNS records still exist. S5 (slot teardown) removes these two sets; nothing else references them.
    static final Set<String> TRANSITIONAL_DOMAIN = Set.of("https://domain-blue.lookahead-dev.internal:8443",
            "https://domain-green.lookahead-dev.internal:8443");
    static final Set<String> TRANSITIONAL_WEB = Set.of("https://web-blue.lookahead-dev.internal:8443",
            "https://web-green.lookahead-dev.internal:8443");

    /** Reads the configured upstreams ({@code LOOKAHEAD_DOMAIN_UPSTREAM}, {@code LOOKAHEAD_WEB_UPSTREAM}). */
    public static DevServiceOrigins from(Environment environment) {
        return of(environment.getProperty(DOMAIN_PROPERTY), environment.getProperty(WEB_PROPERTY));
    }

    public static DevServiceOrigins of(String domain, String web) {
        if (!allowed(domain, DOMAIN, TRANSITIONAL_DOMAIN) || !allowed(web, WEB, TRANSITIONAL_WEB))
            throw new IllegalStateException("Explicit stable DEV Domain and Web upstreams required");
        return new DevServiceOrigins(domain, web);
    }

    private static boolean allowed(String value, String stable, Set<String> transitional) {
        return value != null && (stable.equals(value) || transitional.contains(value));
    }

    public boolean internal(URI uri) {
        return Set.of(URI.create(domain).getHost(), URI.create(web).getHost()).contains(uri.getHost());
    }
}
