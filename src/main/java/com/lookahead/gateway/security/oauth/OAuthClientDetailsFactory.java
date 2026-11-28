package com.lookahead.gateway.security.oauth;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.util.DevServiceOrigins;
import com.lookahead.gateway.util.OAuthLegacyServiceNames;
import java.net.URI;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;

/**
 * Reads and checks the deployment configuration and builds the {@link OAuthClientDetails} from it;
 * refuses the start otherwise.
 */
public final class OAuthClientDetailsFactory {
  private OAuthClientDetailsFactory() {}

  // DLV-969: the settings a refused start names (property and the variable that sets it); never
  // their values.
  static final String ENVIRONMENT = "app.deployment-environment (LOOKAHEAD_ENVIRONMENT)",
      TRANSPORT = "app.oauth.domain-transport (LOOKAHEAD_DOMAIN_TRANSPORT)",
      ISSUER = "app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER)",
      LOCAL_ISSUER = "app.oauth.issuer (LOOKAHEAD_OAUTH_ISSUER)",
      MANAGED_LOGIN = "app.cognito.managed-login (LOOKAHEAD_COGNITO_MANAGED_LOGIN)",
      SCOPE_PREFIX = "app.cognito.scope-prefix (LOOKAHEAD_COGNITO_SCOPE_PREFIX)",
      DOMAIN_SECRET = "app.cognito.gateway-secret (LOOKAHEAD_DOMAIN_GATEWAY_SECRET)",
      CLIENT_ID = "app.oauth.client-id (APP_OAUTH_CLIENT_ID)",
      CLIENT_SECRET = "app.oauth.client-secret (LOOKAHEAD_GATEWAY_CLIENT_SECRET)",
      FRONTEND = "app.oauth.frontend (LOOKAHEAD_FRONTEND_ORIGIN)",
      DOMAIN = "app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM)",
      IDENTITY = "app.oauth.identity-upstream (LOOKAHEAD_IDENTITY_UPSTREAM)";

  public static OAuthClientDetails from(Environment environment) {
    var values =
        Binder.get(environment)
            .bind("app.oauth", OAuthConfigValues.class)
            .orElseThrow(
                () -> OpsLog.startupRefused("app.oauth", "MISSING", "app.oauth is required"));
    if (environment.acceptsProfiles(
        Profiles.of(
            "accounts",
            "oauth-server",
            "resource",
            "domain-api",
            OAuthLegacyServiceNames.DOMAIN_API)))
      throw OpsLog.startupRefused(
          "spring.profiles.active",
          "NOT_ALLOWED",
          "Gateway cannot activate Identity or Learning Domain API roles");
    String mode = environment.getProperty("app.deployment-environment", "");
    if (!Set.of("local", "dev", "prod").contains(mode))
      throw OpsLog.startupRefused(
          ENVIRONMENT,
          mode.isBlank() ? "MISSING" : "INVALID",
          "Explicit local, dev or prod deployment environment required");
    String domainTransport = environment.getProperty("app.oauth.domain-transport", "https");
    if (!Set.of("https", "service-connect-tls", "application-mtls").contains(domainTransport))
      throw OpsLog.startupRefused(
          TRANSPORT, "INVALID", "Explicit supported Domain transport required");
    if ("local".equals(mode) && !"https".equals(domainTransport))
      throw OpsLog.startupRefused(
          TRANSPORT, "NOT_ALLOWED", "Service Connect transport requires DEV/PROD");
    if ("local".equals(mode)
        && environment.acceptsProfiles(Profiles.of("dev", "prod", "production")))
      throw OpsLog.startupRefused(
          "spring.profiles.active", "NOT_ALLOWED", "Local mode cannot activate DEV/PROD profiles");
    if (!"local".equals(mode) && environment.acceptsProfiles(Profiles.of("local", "local-test")))
      throw OpsLog.startupRefused(
          "spring.profiles.active", "NOT_ALLOWED", "Local profiles cannot run in DEV/PROD");
    if (!"local".equals(mode)
        && !environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, true))
      throw OpsLog.startupRefused(
          "server.servlet.session.cookie.secure",
          "NOT_ALLOWED",
          "DEV/PROD session cookies must be Secure");
    String sessionCookie =
        environment.getProperty("server.servlet.session.cookie.name", "LOOKAHEAD_GATEWAY");
    String identityCookie =
        environment.getProperty("app.gateway.identity-cookie-name", "LOOKAHEAD_SESSION");
    if (!sessionCookie.matches("[A-Z][A-Z0-9_]{2,63}")
        || !identityCookie.matches("[A-Z][A-Z0-9_]{2,63}")
        || sessionCookie.equals(identityCookie))
      throw OpsLog.startupRefused(
          !sessionCookie.matches("[A-Z][A-Z0-9_]{2,63}")
              ? "server.servlet.session.cookie.name (LOOKAHEAD_GATEWAY_COOKIE_NAME)"
              : "app.gateway.identity-cookie-name (LOOKAHEAD_IDENTITY_COOKIE_NAME)",
          sessionCookie.equals(identityCookie) ? "SAME_AS_OTHER_COOKIE" : "INVALID",
          "Gateway and Identity require distinct valid cookie names");
    if (!"local".equals(mode)) {
      String issuer = required(ISSUER, environment.getProperty("app.cognito.issuer"));
      if (!issuer.matches(
          "https://cognito-idp\\.[a-z]{2}-[a-z]+-\\d\\.amazonaws\\.com"
              + "/[a-z]{2}-[a-z]+-\\d_[A-Za-z0-9]+"))
        throw OpsLog.startupRefused(ISSUER, "INVALID", "Explicit Cognito pool issuer required");
      String region = OAuthClientDetails.region(issuer);
      if (!URI.create(issuer).getPath().startsWith("/" + region + "_"))
        throw OpsLog.startupRefused(ISSUER, "REGION_MISMATCH", "Cognito pool region mismatch");
      String managed =
          required(MANAGED_LOGIN, environment.getProperty("app.cognito.managed-login"));
      if (!managed.matches(
          "https://[a-z0-9-]+\\.auth\\." + Pattern.quote(region) + "\\.amazoncognito\\.com"))
        throw OpsLog.startupRefused(
            MANAGED_LOGIN, "INVALID", "Explicit regional Cognito managed-login origin required");
      String prefix = required(SCOPE_PREFIX, environment.getProperty("app.cognito.scope-prefix"));
      String serviceSecret =
          required(DOMAIN_SECRET, environment.getProperty("app.cognito.gateway-secret"));
      if (!prefix.matches("[A-Za-z0-9][A-Za-z0-9:._/-]{1,200}")
          || prefix.endsWith("/")
          || !injectedSecret(serviceSecret))
        throw OpsLog.startupRefused(
            injectedSecret(serviceSecret) ? SCOPE_PREFIX : DOMAIN_SECRET,
            "INVALID",
            "Invalid cloud scopes or injected Gateway secret");
      String client = required(CLIENT_ID, values.clientId()),
          secret = required(CLIENT_SECRET, values.clientSecret());
      if (!client.matches("[A-Za-z0-9]{10,128}") || !injectedSecret(secret))
        throw OpsLog.startupRefused(
            injectedSecret(secret) ? CLIENT_ID : CLIENT_SECRET,
            "INVALID",
            "Invalid Cognito client credentials");
      origin(FRONTEND, required(FRONTEND, values.frontend()), false, false);
      String domain = required(DOMAIN, values.domainApiUpstream());
      if ("application-mtls".equals(domainTransport)) {
        if (!"dev".equals(mode)
            || !environment.acceptsProfiles(Profiles.of("lower-cost-dev"))
            || !DevServiceOrigins.from(environment).domain().equals(domain)
            || !environment.getProperty("server.ssl.enabled", Boolean.class, false)
            || !"serving".equals(environment.getProperty("server.ssl.bundle")))
          throw OpsLog.startupRefused(
              !"dev".equals(mode)
                  ? ENVIRONMENT
                  : !environment.acceptsProfiles(Profiles.of("lower-cost-dev"))
                      ? "spring.profiles.active (lower-cost-dev)"
                      : !DevServiceOrigins.from(environment).domain().equals(domain)
                          ? DOMAIN
                          : "server.ssl.enabled / server.ssl.bundle",
              "NOT_ALLOWED",
              "Application mTLS requires the explicit DEV TLS profile and the stable Domain and Web"
                  + " origins");
      } else if ("service-connect-tls".equals(domainTransport)) {
        // The selected ECS client alias routes through its local Service Connect proxy.
        // Infra must require TLS for the inter-task hop; this is not a general HTTP exception.
        if (!"http://domain:8080".equals(domain))
          throw OpsLog.startupRefused(
              DOMAIN, "INVALID", "Service Connect requires the exact Domain client alias");
      } else {
        origin(DOMAIN, domain, false, true);
      }
      return new OAuthClientDetails(
          issuer,
          client,
          secret,
          null,
          values.domainApiUpstream(),
          values.frontend(),
          managed,
          prefix,
          serviceSecret);
    }
    return from(values);
  }

  static OAuthClientDetails from(OAuthConfigValues values) {
    String issuer = required(LOCAL_ISSUER, values.issuer());
    String frontend = required(FRONTEND, values.frontend());
    String secret = required(CLIENT_SECRET, values.clientSecret());
    String client = required(CLIENT_ID, values.clientId());
    if (!client.matches("[a-z][a-z0-9-]{2,79}") || secret.length() < 32)
      throw OpsLog.startupRefused(
          secret.length() < 32 ? CLIENT_SECRET : CLIENT_ID,
          "INVALID",
          "Dedicated OAuth client ID and secret required");
    origin(LOCAL_ISSUER, issuer, true, false);
    origin(FRONTEND, frontend, true, false);
    if (!issuer.equals(frontend))
      throw OpsLog.startupRefused(
          LOCAL_ISSUER, "NOT_SAME_AS_FRONTEND", "Frontend and issuer must share the public origin");
    String identity = required(IDENTITY, values.identityUpstream());
    String domainApi = required(DOMAIN, values.domainApiUpstream());
    origin(IDENTITY, identity, true, true);
    origin(DOMAIN, domainApi, true, true);
    return new OAuthClientDetails(issuer, client, secret, identity, domainApi, frontend);
  }

  private static boolean injectedSecret(String value) {
    return value.length() >= 32
        && value.length() <= 4096
        && !value.startsWith("arn:")
        && !value.startsWith("@")
        && !value.contains("${")
        && !value.contains("{{")
        && value.codePoints().noneMatch(Character::isWhitespace)
        && value.codePoints().noneMatch(Character::isISOControl);
  }

  private static String required(String setting, String value) {
    if (value == null || value.isBlank())
      throw OpsLog.startupRefused(
          setting, "MISSING", "All gateway OAuth endpoints and credentials are required");
    return value;
  }

  private static void origin(String setting, String value, boolean local, boolean service) {
    URI uri;
    try {
      uri = URI.create(value);
    } catch (IllegalArgumentException malformed) {
      throw OpsLog.startupRefused(
          setting,
          "NOT_A_URI",
          "Fixed HTTPS origin required except explicit local service/loopback HTTP");
    }
    boolean localHost =
        Set.of(
                "127.0.0.1",
                "localhost",
                "identity",
                "domain-api",
                OAuthLegacyServiceNames.DOMAIN_API)
            .contains(uri.getHost() == null ? "" : uri.getHost());
    boolean allowedHttp =
        local && localHost && (service || Set.of("127.0.0.1", "localhost").contains(uri.getHost()));
    if (uri.getHost() == null
        || uri.getUserInfo() != null
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null
        || !uri.getRawPath().isEmpty()
        || !("https".equals(uri.getScheme()) || allowedHttp && "http".equals(uri.getScheme())))
      throw OpsLog.startupRefused(
          setting,
          "INVALID",
          "Fixed HTTPS origin required except explicit local service/loopback HTTP");
  }
}
