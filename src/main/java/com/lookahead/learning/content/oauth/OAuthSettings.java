package com.lookahead.learning.content.oauth;

import java.net.URI;
import java.util.Set;
import org.springframework.core.env.Environment;

/** Only deployment configuration selects service destinations. */
public record OAuthSettings(String issuer, String clientId, String clientSecret,
        String identityUpstream, String domainApiUpstream, String frontend, String managedLogin, String scopePrefix, String gatewaySecret) {
    public OAuthSettings(String issuer,String clientId,String clientSecret,String identityUpstream,String domainApiUpstream,String frontend){this(issuer,clientId,clientSecret,identityUpstream,domainApiUpstream,frontend,null,null,null);}
    public boolean cloud(){return managedLogin != null;}
    public static OAuthSettings from(Environment environment) {
        var properties = org.springframework.boot.context.properties.bind.Binder.get(environment)
                .bind("app.oauth", OAuthProperties.class).orElseThrow(() -> new IllegalStateException("app.oauth is required"));
        if (environment.acceptsProfiles(org.springframework.core.env.Profiles.of("accounts", "oauth-server", "resource", "domain-api", LegacyServiceNames.DOMAIN_API)))
            throw new IllegalStateException("Gateway cannot activate Identity or Learning Domain API roles");
        String mode = environment.getProperty("app.deployment-environment", "");
        if (!Set.of("local", "dev", "prod").contains(mode))
            throw new IllegalStateException("Explicit local, dev or prod deployment environment required");
        String domainTransport = environment.getProperty("app.oauth.domain-transport", "https");
        if (!Set.of("https", "service-connect-tls").contains(domainTransport))
            throw new IllegalStateException("Explicit supported Domain transport required");
        if ("local".equals(mode) && !"https".equals(domainTransport))
            throw new IllegalStateException("Service Connect transport requires DEV/PROD");
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
        if (!"local".equals(mode)) {
            String issuer=required(environment.getProperty("app.cognito.issuer"));
            if(!issuer.matches("https://cognito-idp\\.[a-z]{2}-[a-z]+-\\d\\.amazonaws\\.com/[a-z]{2}-[a-z]+-\\d_[A-Za-z0-9]+"))throw new IllegalStateException("Explicit Cognito pool issuer required");
            String region=URI.create(issuer).getHost().split("\\.")[1];
            if(!URI.create(issuer).getPath().startsWith("/"+region+"_"))throw new IllegalStateException("Cognito pool region mismatch");
            String managed=required(environment.getProperty("app.cognito.managed-login"));
            if(!managed.matches("https://[a-z0-9-]+\\.auth\\."+java.util.regex.Pattern.quote(region)+"\\.amazoncognito\\.com"))throw new IllegalStateException("Explicit regional Cognito managed-login origin required");
            String prefix=required(environment.getProperty("app.cognito.scope-prefix"));
            String serviceSecret=required(environment.getProperty("app.cognito.gateway-secret"));
            if(!prefix.matches("[A-Za-z0-9][A-Za-z0-9:._/-]{1,200}")||prefix.endsWith("/")||!injectedSecret(serviceSecret))throw new IllegalStateException("Invalid cloud scopes or injected Gateway secret");
            String client=required(properties.clientId()), secret=required(properties.clientSecret());
            if(!client.matches("[A-Za-z0-9]{10,128}")||!injectedSecret(secret))throw new IllegalStateException("Invalid Cognito client credentials");
            origin(required(properties.frontend()),false,false);
            String domain = required(properties.domainApiUpstream());
            if ("service-connect-tls".equals(domainTransport)) {
                // The selected ECS client alias routes through its local Service Connect proxy.
                // Infra must require TLS for the inter-task hop; this is not a general HTTP exception.
                if (!"http://domain:8080".equals(domain))
                    throw new IllegalStateException("Service Connect requires the exact Domain client alias");
            } else {
                origin(domain,false,true);
            }
            return new OAuthSettings(issuer,client,secret,null,properties.domainApiUpstream(),properties.frontend(),managed,prefix,serviceSecret);
        }
        return from(properties, true);
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
        String domainApi = required(properties.domainApiUpstream());
        origin(identity, local, true); origin(domainApi, local, true);
        return new OAuthSettings(issuer, client, secret, identity, domainApi, frontend);
    }
    private static boolean injectedSecret(String value) {
        return value.length() >= 32 && value.length() <= 4096
                && !value.startsWith("arn:") && !value.startsWith("@")
                && !value.contains("${") && !value.contains("{{")
                && value.codePoints().noneMatch(Character::isWhitespace)
                && value.codePoints().noneMatch(Character::isISOControl);
    }
    private static String required(String value) {
        if (value == null || value.isBlank()) throw new IllegalStateException("All gateway OAuth endpoints and credentials are required");
        return value;
    }
    private static void origin(String value, boolean local, boolean service) {
        URI uri = URI.create(value);
        boolean localHost = Set.of("127.0.0.1", "localhost", "identity", "domain-api", LegacyServiceNames.DOMAIN_API).contains(uri.getHost() == null ? "" : uri.getHost());
        boolean allowedHttp = local && localHost && (service || Set.of("127.0.0.1", "localhost").contains(uri.getHost()));
        if (uri.getHost() == null || uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || !uri.getRawPath().isEmpty() || !("https".equals(uri.getScheme()) || allowedHttp && "http".equals(uri.getScheme())))
            throw new IllegalStateException("Fixed HTTPS origin required except explicit local service/loopback HTTP");
    }
    @Override public String toString() { return "OAuthSettings[redacted]"; }
}
