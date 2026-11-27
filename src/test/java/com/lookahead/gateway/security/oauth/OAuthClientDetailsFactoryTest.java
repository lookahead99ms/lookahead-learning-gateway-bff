package com.lookahead.gateway.security.oauth;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

/**
 * The deployment configuration read and checked by OAuthClientDetailsFactory. The cases at the top give the properties
 * directly; the groups below read the real application.yml, check the line a refused start writes, and check the DEV
 * bindings the Domain expects. {@code environment()}, {@code production()} and {@code cloudEnvironment(mode)} are also
 * the fixtures other tests build their OAuthClientDetails from.
 */
public class OAuthClientDetailsFactoryTest {
    MockEnvironment environment() {
        return new MockEnvironment().withProperty("app.deployment-environment", "local")
                .withProperty("app.oauth.issuer", "http://127.0.0.1:4350")
                .withProperty("app.oauth.frontend", "http://127.0.0.1:4350")
                .withProperty("app.oauth.client-id", "lookahead-candidate")
                .withProperty("app.oauth.client-secret", "synthetic-gateway-secret-never-used-outside-test")
                .withProperty("app.oauth.identity-upstream", "http://identity:8080")
                .withProperty("app.oauth.domain-api-upstream", "http://domain-api:8080");
    }
    @Test void requiresTwoFixedServiceOriginsAndRedactsSecret() {
        var oauth = OAuthClientDetailsFactory.from(environment());
        assertThat(oauth.identityUpstream()).isEqualTo("http://identity:8080");
        assertThat(oauth.domainApiUpstream()).isEqualTo("http://domain-api:8080");
        // An existing local container may still advertise the historical service name.
        assertThat(OAuthClientDetailsFactory.from(environment().withProperty("app.oauth.domain-api-upstream", "http://platform:8080"))
                .domainApiUpstream()).isEqualTo("http://platform:8080");
        assertThat(oauth.toString()).doesNotContain(oauth.clientSecret());
        for (String invalid : new String[]{"", "file:///etc/passwd", "http://attacker.test", "http://user@identity:8080", "http://identity:8080/path", "http://identity:8080?x=y"})
            assertThatException().isThrownBy(() -> OAuthClientDetailsFactory.from(environment().withProperty("app.oauth.identity-upstream", invalid)));
    }
    @Test void rejectsAmbiguousEnvironmentAndMixedProfiles() {
        for (String mode : new String[]{"", "production", "development", "unknown"})
            assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(environment().withProperty("app.deployment-environment", mode)));
        // Reject the retired Domain API profile as well as the canonical name.
        for (String role : new String[]{"accounts", "oauth-server", "resource", "domain-api", "platform"}) {
            var mixed = environment(); mixed.setActiveProfiles("gateway", role);
            assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(mixed));
        }
        var localWithProd = environment(); localWithProd.setActiveProfiles("prod");
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(localWithProd));
        var prodWithLocal = production(); prodWithLocal.setActiveProfiles("local");
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(prodWithLocal));
    }
    @Test void productionRequiresHttpsAndSecureDistinctCookie() {
        assertThat(OAuthClientDetailsFactory.from(production()).issuer()).isEqualTo("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example");
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(production().withProperty("server.servlet.session.cookie.secure", "false")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(production().withProperty("server.servlet.session.cookie.name", "LOOKAHEAD_SESSION")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(production().withProperty("app.oauth.domain-api-upstream", "http://domain-api:8080")));
    }
    @Test void cloudCredentialsRequireInjectedValuesInDevAndProd() {
        for (String mode : new String[]{"dev", "prod"}) {
            for (String property : new String[]{"app.cognito.gateway-secret", "app.oauth.client-secret"}) {
                for (String invalid : new String[]{"arn:aws:secretsmanager:us-east-2:000000000000:secret:example",
                        "${LOOKAHEAD_UNRESOLVED_SECRET_PLACEHOLDER}", "@application.veryLongSecretReference",
                        "{{resolve:secretsmanager:example-secret-value}}", "x".repeat(33) + "\n",
                        "x".repeat(33) + " ", "x".repeat(4097), "short"}) {
                    assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> OAuthClientDetailsFactory.from(production()
                            .withProperty("app.deployment-environment", mode).withProperty(property, invalid)));
                }
            }
            assertThat(OAuthClientDetailsFactory.from(production().withProperty("app.deployment-environment", mode)).cloud()).isTrue();
        }
    }
    public MockEnvironment production() {
        return environment().withProperty("app.deployment-environment", "prod")
                .withProperty("app.oauth.issuer", "https://learn.example.test")
                .withProperty("app.cognito.issuer","https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example")
                .withProperty("app.cognito.managed-login","https://example.auth.us-east-2.amazoncognito.com")
                .withProperty("app.cognito.scope-prefix","lookahead")
                .withProperty("app.cognito.gateway-secret","synthetic-internal-gateway-secret-for-fixtures")
                .withProperty("app.oauth.client-id","syntheticclient123456")
                .withProperty("app.oauth.frontend", "https://learn.example.test")
                .withProperty("app.oauth.identity-upstream", "https://identity.example.test")
                .withProperty("app.oauth.domain-api-upstream", "https://domain-api.example.test");
    }

    public static MockEnvironment cloudEnvironment(String mode) throws Exception {
        var environment = yamlEnvironment(mode);
        String region = mode.equals("dev") ? "us-east-2" : "us-west-2";
        return environment
                .withProperty("LOOKAHEAD_FRONTEND_ORIGIN", "https://" + mode + "-learn.example.test")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "https://" + mode + "-domain.example.test")
                .withProperty("LOOKAHEAD_COGNITO_ISSUER", "https://cognito-idp." + region + ".amazonaws.com/" + region + "_Example")
                .withProperty("LOOKAHEAD_COGNITO_MANAGED_LOGIN", "https://" + mode + "-example.auth." + region + ".amazoncognito.com")
                .withProperty("LOOKAHEAD_COGNITO_SCOPE_PREFIX", "lookahead-" + mode)
                .withProperty("APP_OAUTH_CLIENT_ID", "synthetic" + mode + "client12345")
                .withProperty("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-" + mode + "-internal-secret-not-for-deployment")
                .withProperty("LOOKAHEAD_GATEWAY_COOKIE_NAME", "LOOKAHEAD_" + mode.toUpperCase() + "_GATEWAY");
    }

    private static MockEnvironment yamlEnvironment(String mode) throws Exception {
        var environment = new MockEnvironment()
                .withProperty("LOOKAHEAD_ENVIRONMENT", mode)
                .withProperty("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "synthetic-" + mode + "-client-secret-not-for-deployment");
        environment.setActiveProfiles("gateway", mode);
        new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"))
                .forEach(source -> environment.getPropertySources().addLast(source));
        return environment;
    }

    /** Exercise deployed environment names through the actual application.yml placeholders. */
    @Nested class Environment {
    @Test void localYamlKeepsIdentityHttpAndNeverRequiresCognitoSettings() throws Exception {
        var environment = yamlEnvironment("local")
                .withProperty("LOOKAHEAD_FRONTEND_ORIGIN", "http://127.0.0.1:4301")
                .withProperty("LOOKAHEAD_OAUTH_ISSUER", "http://127.0.0.1:4301")
                .withProperty("LOOKAHEAD_IDENTITY_UPSTREAM", "http://identity:8080")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain-api:8080");
        var oauth = OAuthClientDetailsFactory.from(environment);
        var registration = new OAuthClientConfiguration().oauthClientRegistrations(oauth).findByRegistrationId("lookahead");
        assertThat(oauth.cloud()).isFalse();
        assertThat(oauth.domainSecret()).isNull();
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("http://127.0.0.1:4301/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo("http://identity:8080/oauth2/token");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("http://identity:8080/oauth2/jwks");
        assertThat(registration.getScopes()).containsExactlyInAnyOrder("openid", "profile", "account", "content", "support");
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void cloudYamlWiresOwnProviderScopesSecretsAndSecureCookiesWithoutIdentity(String mode) throws Exception {
        var environment = cloudEnvironment(mode);
        var oauth = OAuthClientDetailsFactory.from(environment);
        var registration = new OAuthClientConfiguration().oauthClientRegistrations(oauth).findByRegistrationId("lookahead");
        String region = mode.equals("dev") ? "us-east-2" : "us-west-2";
        assertThat(oauth.cloud()).isTrue();
        assertThat(oauth.identityUpstream()).isNull();
        assertThat(oauth.frontend()).isEqualTo("https://" + mode + "-learn.example.test");
        assertThat(oauth.domainApiUpstream()).isEqualTo("https://" + mode + "-domain.example.test");
        assertThat(oauth.domainSecret()).isEqualTo("synthetic-" + mode + "-internal-secret-not-for-deployment");
        assertThat(registration.getClientId()).isEqualTo("synthetic" + mode + "client12345");
        assertThat(registration.getRedirectUri()).isEqualTo("https://" + mode + "-learn.example.test/login/oauth2/code/lookahead");
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/token");
        assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/userInfo");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("https://cognito-idp." + region + ".amazonaws.com/" + region + "_Example/.well-known/jwks.json");
        assertThat(registration.getScopes()).containsExactlyInAnyOrder("openid", "profile", "email", "aws.cognito.signin.user.admin", "lookahead-" + mode + "/account", "lookahead-" + mode + "/content", "lookahead-" + mode + "/support");
        assertThat(environment.getProperty("server.servlet.session.cookie.secure", Boolean.class)).isTrue();
        assertThat(environment.getProperty("server.servlet.session.cookie.http-only", Boolean.class)).isTrue();
        assertThat(environment.getProperty("server.servlet.session.cookie.same-site")).isEqualTo("lax");
        assertThat(environment.getProperty("server.servlet.session.cookie.name")).isEqualTo("LOOKAHEAD_" + mode.toUpperCase() + "_GATEWAY");
        assertThat(oauth.toString()).doesNotContain(oauth.clientSecret(), oauth.domainSecret());
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void serviceConnectAcceptsOnlyTheSelectedLocalProxyAliasAndKeepsProviderHttps(String mode) throws Exception {
        var environment = cloudEnvironment(mode)
                .withProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "service-connect-tls")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain:8080");
        var oauth = OAuthClientDetailsFactory.from(environment);
        assertThat(oauth.domainApiUpstream()).isEqualTo("http://domain:8080");
        var provider = new OAuthClientConfiguration().oauthClientRegistrations(oauth)
                .findByRegistrationId("lookahead").getProviderDetails();
        assertThat(provider.getTokenUri()).startsWith("https://");
        assertThat(provider.getJwkSetUri()).startsWith("https://cognito-idp.");
        assertThat(provider.getUserInfoEndpoint().getUri()).startsWith("https://");
        for (String endpoint : new String[]{"http://domain", "http://domain:80", "http://domain:8081",
                "http://domain-api:8080", "http://127.0.0.1:8080", "http://localhost:8080",
                "http://domain.lookahead-dev.internal:8080", "http://domain.attacker.test:8080",
                "http://domain:8080/", "http://domain:8080/api", "http://domain:8080?x=y",
                "http://domain:8080#fragment", "http://user@domain:8080", "http://domain:8080@attacker.test",
                "http://DOMAIN:8080", "http://%64omain:8080", "https://domain:8080", " http://domain:8080"}) {
            environment.setProperty("LOOKAHEAD_DOMAIN_UPSTREAM", endpoint);
            assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).as(mode + " rejects " + endpoint)
                    .isInstanceOf(IllegalStateException.class);
        }
        for (String transport : new String[]{"", "http", "service-connect", "SERVICE-CONNECT-TLS", "service-connect-tls "}) {
            environment.setProperty("LOOKAHEAD_DOMAIN_TRANSPORT", transport);
            assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).as(mode + " rejects mode " + transport)
                    .isInstanceOf(IllegalStateException.class);
        }
        environment.setProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "https");
        environment.setProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain:8080");
        assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).isInstanceOf(IllegalStateException.class);
    }

    @Test void localCannotAccidentallySelectCloudServiceConnectTransport() throws Exception {
        var environment = yamlEnvironment("local")
                .withProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "service-connect-tls");
        assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requires DEV/PROD");
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void eachCloudEnvironmentRejectsMissingCredentialsUnsafeOriginsAndCrossRegionProvider(String mode) throws Exception {
        String[][] invalid = {
                {"LOOKAHEAD_GATEWAY_CLIENT_SECRET", ""}, {"LOOKAHEAD_DOMAIN_GATEWAY_SECRET", ""},
                {"APP_OAUTH_CLIENT_ID", "lookahead-web-gateway"}, {"LOOKAHEAD_COGNITO_SCOPE_PREFIX", "bad scope"},
                {"LOOKAHEAD_COGNITO_ISSUER", "https://identity.example.test"},
                {"LOOKAHEAD_COGNITO_ISSUER", "https://cognito-idp.us-east-2.amazonaws.com/us-west-2_Example"},
                {"LOOKAHEAD_COGNITO_MANAGED_LOGIN", "https://example.auth.eu-west-1.amazoncognito.com"},
                {"LOOKAHEAD_FRONTEND_ORIGIN", "http://127.0.0.1:4301"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain-api:8080"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://user:password@domain.example.test"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test/path"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test?redirect=elsewhere"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test#fragment"}
        };
        for (var setting : invalid) {
            var environment = cloudEnvironment(mode).withProperty(setting[0], setting[1]);
            assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).as(mode + " rejects " + setting[0]).isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> OAuthClientDetailsFactory.from(cloudEnvironment(mode).withProperty("server.servlet.session.cookie.secure", "false"))).isInstanceOf(IllegalStateException.class);
        var mixed = cloudEnvironment(mode); mixed.setActiveProfiles("gateway", "local");
        assertThatThrownBy(() -> OAuthClientDetailsFactory.from(mixed)).isInstanceOf(IllegalStateException.class);
    }
    }

    /** DLV-969 (owner, 2026-11-04): a refused start names the setting and why, never its value; the exception is unchanged. */
    @Nested class StartupRefusal {
    final LogCapture log = new LogCapture("lookahead.lifecycle");
    final OAuthClientDetailsFactoryTest fixtures = new OAuthClientDetailsFactoryTest();

    @AfterEach void close() { log.close(); }

    void refused(MockEnvironment environment, String message, String setting, String reason, String... secrets) {
        log.clear();
        assertThatIllegalStateException().isThrownBy(() -> OAuthClientDetailsFactory.from(environment)).withMessage(message).withNoCause();
        assertThat(log.lines()).hasSize(1);
        var line = log.last();
        assertThat(line.getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(line)).contains("event.action=startup.refused", "event.outcome=failure", "setting=" + setting, "reason=" + reason);
        assertThat(line.getFormattedMessage()).startsWith("Startup refused: " + setting + " ").contains("(" + reason + "): " + message)
                .endsWith("; the Gateway will not start");
        log.assertNothing(secrets);
    }

    @Test void cloudSettingsNameTheVariableThatIsMissingOrWrong() {
        refused(fixtures.production().withProperty("app.cognito.issuer", ""), "All gateway OAuth endpoints and credentials are required",
                "app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER)", "MISSING");
        refused(fixtures.production().withProperty("app.cognito.issuer", "https://cognito-idp.us-east-2.amazonaws.com/us-west-2_Example"),
                "Cognito pool region mismatch", "app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER)", "REGION_MISMATCH");
        refused(fixtures.production().withProperty("app.cognito.managed-login", "https://synthetic-private.example.test"),
                "Explicit regional Cognito managed-login origin required", "app.cognito.managed-login (LOOKAHEAD_COGNITO_MANAGED_LOGIN)", "INVALID",
                "synthetic-private");
        refused(fixtures.production().withProperty("app.oauth.client-secret", "short-synthetic-secret"), "Invalid Cognito client credentials",
                "app.oauth.client-secret (LOOKAHEAD_GATEWAY_CLIENT_SECRET)", "INVALID", "short-synthetic-secret");
        refused(fixtures.production().withProperty("app.oauth.client-id", "bad-id"), "Invalid Cognito client credentials",
                "app.oauth.client-id (APP_OAUTH_CLIENT_ID)", "INVALID", "bad-id");
        refused(fixtures.production().withProperty("app.cognito.gateway-secret", "arn:aws:secretsmanager:us-east-2:000000000000:secret:synthetic"),
                "Invalid cloud scopes or injected Gateway secret", "app.cognito.gateway-secret (LOOKAHEAD_DOMAIN_GATEWAY_SECRET)", "INVALID", "secretsmanager");
        refused(fixtures.production().withProperty("app.cognito.scope-prefix", "bad/"), "Invalid cloud scopes or injected Gateway secret",
                "app.cognito.scope-prefix (LOOKAHEAD_COGNITO_SCOPE_PREFIX)", "INVALID");
        refused(fixtures.production().withProperty("app.oauth.domain-api-upstream", "https://user:synthetic-password@domain.example.test"),
                "Fixed HTTPS origin required except explicit local service/loopback HTTP", "app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM)",
                "INVALID", "synthetic-password");
        refused(fixtures.production().withProperty("app.oauth.domain-transport", "service-connect-tls"), "Service Connect requires the exact Domain client alias",
                "app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM)", "INVALID");
        refused(fixtures.production().withProperty("app.oauth.domain-transport", "application-mtls"),
                "Application mTLS requires the explicit DEV TLS profile and the stable Domain and Web origins",
                "app.deployment-environment (LOOKAHEAD_ENVIRONMENT)", "NOT_ALLOWED");
        var notDevProfile = fixtures.production().withProperty("app.deployment-environment", "dev").withProperty("app.oauth.domain-transport", "application-mtls");
        refused(notDevProfile, "Application mTLS requires the explicit DEV TLS profile and the stable Domain and Web origins",
                "spring.profiles.active (lower-cost-dev)", "NOT_ALLOWED");
        var dev = fixtures.production().withProperty("app.deployment-environment", "dev").withProperty("app.oauth.domain-transport", "application-mtls")
                .withProperty(DevServiceOrigins.DOMAIN_PROPERTY, DevServiceOrigins.DOMAIN).withProperty(DevServiceOrigins.WEB_PROPERTY, DevServiceOrigins.WEB);
        dev.setActiveProfiles("lower-cost-dev");
        refused(dev, "Application mTLS requires the explicit DEV TLS profile and the stable Domain and Web origins",
                "server.ssl.enabled / server.ssl.bundle", "NOT_ALLOWED");
        refused(fixtures.production().withProperty("server.servlet.session.cookie.secure", "false"), "DEV/PROD session cookies must be Secure",
                "server.servlet.session.cookie.secure", "NOT_ALLOWED");
    }

    @Test void deploymentProfilesAndCookieNamesAreNamedToo() {
        refused(fixtures.environment().withProperty("app.deployment-environment", ""), "Explicit local, dev or prod deployment environment required",
                "app.deployment-environment (LOOKAHEAD_ENVIRONMENT)", "MISSING");
        refused(fixtures.environment().withProperty("app.deployment-environment", "production"), "Explicit local, dev or prod deployment environment required",
                "app.deployment-environment (LOOKAHEAD_ENVIRONMENT)", "INVALID");
        refused(fixtures.environment().withProperty("app.oauth.domain-transport", "carrier-pigeon"), "Explicit supported Domain transport required",
                "app.oauth.domain-transport (LOOKAHEAD_DOMAIN_TRANSPORT)", "INVALID");
        refused(fixtures.environment().withProperty("app.oauth.domain-transport", "application-mtls"), "Service Connect transport requires DEV/PROD",
                "app.oauth.domain-transport (LOOKAHEAD_DOMAIN_TRANSPORT)", "NOT_ALLOWED");
        var role = fixtures.environment(); role.setActiveProfiles("gateway", "accounts");
        refused(role, "Gateway cannot activate Identity or Learning Domain API roles", "spring.profiles.active", "NOT_ALLOWED");
        var localWithProd = fixtures.environment(); localWithProd.setActiveProfiles("prod");
        refused(localWithProd, "Local mode cannot activate DEV/PROD profiles", "spring.profiles.active", "NOT_ALLOWED");
        refused(fixtures.environment().withProperty("app.gateway.identity-cookie-name", "LOOKAHEAD_GATEWAY"),
                "Gateway and Identity require distinct valid cookie names", "app.gateway.identity-cookie-name (LOOKAHEAD_IDENTITY_COOKIE_NAME)",
                "SAME_AS_OTHER_COOKIE");
        refused(fixtures.environment().withProperty("server.servlet.session.cookie.name", "bad"),
                "Gateway and Identity require distinct valid cookie names", "server.servlet.session.cookie.name (LOOKAHEAD_GATEWAY_COOKIE_NAME)", "INVALID");
    }

    @Test void localSettingsNameTheVariableAndAnUnparseableOriginStaysOutOfTheLog() {
        refused(fixtures.environment().withProperty("app.oauth.identity-upstream", ""), "All gateway OAuth endpoints and credentials are required",
                "app.oauth.identity-upstream (LOOKAHEAD_IDENTITY_UPSTREAM)", "MISSING");
        refused(fixtures.environment().withProperty("app.oauth.client-secret", "short"), "Dedicated OAuth client ID and secret required",
                "app.oauth.client-secret (LOOKAHEAD_GATEWAY_CLIENT_SECRET)", "INVALID");
        refused(fixtures.environment().withProperty("app.oauth.client-id", "Bad Id"), "Dedicated OAuth client ID and secret required",
                "app.oauth.client-id (APP_OAUTH_CLIENT_ID)", "INVALID");
        refused(fixtures.environment().withProperty("app.oauth.issuer", "http://localhost:4350"), "Frontend and issuer must share the public origin",
                "app.oauth.issuer (LOOKAHEAD_OAUTH_ISSUER)", "NOT_SAME_AS_FRONTEND");
        // A malformed origin used to escape as IllegalArgumentException quoting the value; now it is a named refusal.
        refused(fixtures.environment().withProperty("app.oauth.domain-api-upstream", "http://synthetic private host:8080"),
                "Fixed HTTPS origin required except explicit local service/loopback HTTP", "app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM)",
                "NOT_A_URI", "synthetic private host");
    }
    }

    /**
     * DLV-914 / DLV-968 S3: the bindings Domain's DEV activation contract (docs/dev-activation.md) expects from the Gateway BFF.
     * The stable Domain DNS name on application mTLS 8443; Domain's loopback 8081 is readiness only, never an upstream;
     * the same application issuer, client and scopes Domain verifies; one DomainGateway secret binding.
     */
    @Nested class DomainBindings {
    static final String ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example";

    static final String DOMAIN = "https://domain.lookahead-dev.internal:8443";
    static final String WEB = "https://web.lookahead-dev.internal:8443";

    MockEnvironment devMutualTls() {
        var environment = new MockEnvironment()
                .withProperty("app.deployment-environment", "dev")
                .withProperty("app.oauth.domain-transport", "application-mtls")
                .withProperty("app.oauth.frontend", "https://dev.example.test")
                .withProperty("app.oauth.domain-api-upstream", DOMAIN)
                .withProperty("app.gateway.web-upstream", WEB)
                .withProperty("app.oauth.client-id", "syntheticlearnerclient1")
                .withProperty("app.oauth.client-secret", "synthetic-learner-client-secret-never-deployed")
                .withProperty("app.cognito.issuer", ISSUER)
                .withProperty("app.cognito.managed-login", "https://dev-example.auth.us-east-2.amazoncognito.com")
                .withProperty("app.cognito.scope-prefix", "lookahead-dev")
                .withProperty("app.cognito.gateway-secret", "synthetic-domain-gateway-secret-never-deployed")
                .withProperty("server.ssl.enabled", "true").withProperty("server.ssl.bundle", "serving");
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        return environment;
    }

    @Test void domainUpstreamIsTheStableDnsNameOnApplicationMutualTls8443() {
        var oauth = OAuthClientDetailsFactory.from(devMutualTls());
        assertThat(oauth.domainApiUpstream()).isEqualTo(DOMAIN);
        var origins = DevServiceOrigins.from(devMutualTls());
        assertThat(origins.domain()).isEqualTo(oauth.domainApiUpstream());
        assertThat(origins.web()).isEqualTo(WEB);
        // Domain's 8081 is loopback readiness; plaintext, bare hostnames, paths, Web and look-alike names are not Domain upstreams.
        for (String rejected : List.of("https://domain.lookahead-dev.internal:8081", "https://domain.lookahead-dev.internal",
                "http://domain.lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal:8443/api",
                "https://domain-red.lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal.attacker.test:8443",
                "https://web.lookahead-dev.internal:8443", "http://domain:8080")) {
            var environment = devMutualTls().withProperty("app.oauth.domain-api-upstream", rejected);
            assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).as(rejected).isInstanceOf(IllegalStateException.class);
        }
        // The Web upstream is validated at the same gate: missing, wrong port or a foreign host denies startup.
        for (String rejected : List.of("", "https://web.lookahead-dev.internal:8081", "https://web.attacker.test:8443", DOMAIN)) {
            var environment = devMutualTls().withProperty("app.gateway.web-upstream", rejected);
            assertThatThrownBy(() -> OAuthClientDetailsFactory.from(environment)).as(rejected).isInstanceOf(IllegalStateException.class);
        }
        // Application mTLS needs the explicit DEV TLS profile; the Service Connect alias is not accepted in this mode.
        var noTls = devMutualTls().withProperty("server.ssl.enabled", "false");
        assertThatThrownBy(() -> OAuthClientDetailsFactory.from(noTls)).isInstanceOf(IllegalStateException.class);
    }

    /** DLV-968 S3, 2026-11-01: transitional until S5 removes the slot services; delete with DevServiceOrigins.TRANSITIONAL_*. */
    @ParameterizedTest @ValueSource(strings = {"blue", "green"})
    void retiredSlotNamesStillPassUntilSlotTeardown(String slot) {
        var environment = devMutualTls().withProperty("app.oauth.domain-api-upstream", "https://domain-" + slot + ".lookahead-dev.internal:8443")
                .withProperty("app.gateway.web-upstream", "https://web-" + slot + ".lookahead-dev.internal:8443");
        assertThat(OAuthClientDetailsFactory.from(environment).domainApiUpstream()).isEqualTo("https://domain-" + slot + ".lookahead-dev.internal:8443");
        assertThat(DevServiceOrigins.from(environment).web()).isEqualTo("https://web-" + slot + ".lookahead-dev.internal:8443");
    }

    @Test void gatewayRequestsExactlyTheScopesAndClientDomainVerifies() {
        var oauth = OAuthClientDetailsFactory.from(devMutualTls());
        var registration = new OAuthClientConfiguration().oauthClientRegistrations(oauth).findByRegistrationId("lookahead");
        // Domain's SignInTokenVerifier requires issuer, client_id and these four scopes on every forwarded access token.
        assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(ISSUER);
        assertThat(registration.getClientId()).isEqualTo("syntheticlearnerclient1");
        assertThat(registration.getScopes()).contains("aws.cognito.signin.user.admin", "lookahead-dev/account", "lookahead-dev/content", "lookahead-dev/support");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(ISSUER + "/.well-known/jwks.json");
        // One shared DomainGateway scalar: Gateway BFF sends it as X-LookAhead-Gateway-Secret, Domain compares the exact bytes.
        assertThat(oauth.domainSecret()).isEqualTo("synthetic-domain-gateway-secret-never-deployed");
        assertThat(oauth.toString()).doesNotContain(oauth.domainSecret());
    }
    }
}
