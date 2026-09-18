package com.lookahead.learning.content.oauth;

import java.net.URI;
import java.util.Set;
import org.springframework.core.env.Environment;

/** Only deployment configuration selects service destinations. */
public record OAuthSettings(String issuer, String clientId, String clientSecret,
        String identityUpstream, String platformUpstream, String frontend) {
    public static OAuthSettings from(Environment environment) {
        var properties = org.springframework.boot.context.properties.bind.Binder.get(environment)
                .bind("app.oauth", OAuthProperties.class).orElseThrow(() -> new IllegalStateException("app.oauth is required"));
        if (environment.acceptsProfiles(org.springframework.core.env.Profiles.of("accounts", "oauth-server", "resource", "platform")))
            throw new IllegalStateException("Gateway cannot activate Identity or Platform roles");
        String mode = environment.getProperty("app.deployment-environment", "");
        if (!Set.of("local", "dev", "prod").contains(mode))
            throw new IllegalStateException("Explicit local, dev or prod deployment environment required");
        if ("local".equals(mode) && environment.acceptsProfiles(org.springframework.core.env.Profiles.of("dev", "prod", "production")))
            throw new IllegalStateException("Local mode cannot activate DEV/PROD profiles");
        if (!"local".equals(mode) && environment.acceptsProfiles(org.springframework.core.env.Profiles.of("local", "local-test")))
            throw new IllegalStateException("Local profiles cannot run in DEV/PROD");
        if (!"local".equals(mode) && !environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, true))
            throw new IllegalStateException("DEV/PROD session cookies must be Secure");
        String gatewayCookie = environment.getProperty("server.servlet.session.cookie.name", "LOOKAHEAD_GATEWAY");
        String identityCookie = environment.getProperty("app.gateway.identity-cookie-name", "LOOKAHEAD_SESSION");
        if (!gatewayCookie.matches("[A-Z][A-Z0-9_]{2,63}") || !identityCookie.matches("[A-Z][A-Z0-9_]{2,63}") || gatewayCookie.equals(identityCookie))
            throw new IllegalStateException("Gateway and Identity require distinct valid cookie names");
        return from(properties, "local".equals(mode));
    }
    static OAuthSettings from(OAuthProperties properties, boolean local) {
        String issuer = required(properties.issuer());
        String frontend = required(properties.frontend());
        String secret = required(properties.clientSecret());
        String client = required(properties.clientId());
        if (!client.matches("[a-z][a-z0-9-]{2,79}") || secret.length() < 32)
            throw new IllegalStateException("Dedicated OAuth client ID and secret required");
        origin(issuer, local, false); origin(frontend, local, false);
        if (!issuer.equals(frontend)) throw new IllegalStateException("Frontend and issuer must share the public origin");
        String identity = required(properties.identityUpstream());
        String platform = required(properties.platformUpstream());
        origin(identity, local, true); origin(platform, local, true);
        return new OAuthSettings(issuer, client, secret, identity, platform, frontend);
    }
    private static String required(String value) {
        if (value == null || value.isBlank()) throw new IllegalStateException("All gateway OAuth endpoints and credentials are required");
        return value;
    }
    private static void origin(String value, boolean local, boolean service) {
        URI uri = URI.create(value);
        boolean localHost = Set.of("127.0.0.1", "localhost", "identity", "platform").contains(uri.getHost() == null ? "" : uri.getHost());
        boolean allowedHttp = local && localHost && (service || Set.of("127.0.0.1", "localhost").contains(uri.getHost()));
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !uri.getRawPath().isEmpty() || !("https".equals(uri.getScheme()) || allowedHttp && "http".equals(uri.getScheme())))
            throw new IllegalStateException("Fixed HTTPS origin required except explicit local service/loopback HTTP");
    }
    @Override public String toString() { return "OAuthSettings[redacted]"; }
}
