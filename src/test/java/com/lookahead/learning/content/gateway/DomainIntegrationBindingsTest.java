package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.DevServiceOrigins;
import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

/**
 * DLV-914 / DLV-968 S3: the bindings Domain's DEV activation contract (docs/dev-activation.md) expects from the Gateway.
 * The stable Domain DNS name on application mTLS 8443; Domain's loopback 8081 is readiness only, never an upstream;
 * the same application issuer, client and scopes Domain verifies; one DomainGateway secret binding.
 */
class DomainIntegrationBindingsTest {
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
        var settings = OAuthSettings.from(devMutualTls());
        assertThat(settings.domainApiUpstream()).isEqualTo(DOMAIN);
        var origins = DevServiceOrigins.from(devMutualTls());
        assertThat(origins.domain()).isEqualTo(settings.domainApiUpstream());
        assertThat(origins.web()).isEqualTo(WEB);
        // Domain's 8081 is loopback readiness; plaintext, bare hostnames, paths, Web and look-alike names are not Domain upstreams.
        for (String rejected : List.of("https://domain.lookahead-dev.internal:8081", "https://domain.lookahead-dev.internal",
                "http://domain.lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal:8443/api",
                "https://domain-red.lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal.attacker.test:8443",
                "https://web.lookahead-dev.internal:8443", "http://domain:8080")) {
            var environment = devMutualTls().withProperty("app.oauth.domain-api-upstream", rejected);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(rejected).isInstanceOf(IllegalStateException.class);
        }
        // The Web upstream is validated at the same gate: missing, wrong port or a foreign host denies startup.
        for (String rejected : List.of("", "https://web.lookahead-dev.internal:8081", "https://web.attacker.test:8443", DOMAIN)) {
            var environment = devMutualTls().withProperty("app.gateway.web-upstream", rejected);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(rejected).isInstanceOf(IllegalStateException.class);
        }
        // Application mTLS needs the explicit DEV TLS profile; the Service Connect alias is not accepted in this mode.
        var noTls = devMutualTls().withProperty("server.ssl.enabled", "false");
        assertThatThrownBy(() -> OAuthSettings.from(noTls)).isInstanceOf(IllegalStateException.class);
    }

    /** DLV-968 S3, 2026-11-01: transitional until S5 removes the slot services; delete with DevServiceOrigins.TRANSITIONAL_*. */
    @ParameterizedTest @ValueSource(strings = {"blue", "green"})
    void retiredSlotNamesStillPassUntilSlotTeardown(String slot) {
        var environment = devMutualTls().withProperty("app.oauth.domain-api-upstream", "https://domain-" + slot + ".lookahead-dev.internal:8443")
                .withProperty("app.gateway.web-upstream", "https://web-" + slot + ".lookahead-dev.internal:8443");
        assertThat(OAuthSettings.from(environment).domainApiUpstream()).isEqualTo("https://domain-" + slot + ".lookahead-dev.internal:8443");
        assertThat(DevServiceOrigins.from(environment).web()).isEqualTo("https://web-" + slot + ".lookahead-dev.internal:8443");
    }

    @Test void internalClientRefusesDomainReadinessPortAndPlaintextBeforeConnecting() {
        var registry = new DefaultSslBundleRegistry();
        registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
        var environment = devMutualTls();
        var properties = new OAuthProperties(null, "https://dev.example.test", "synthetic-learner-client-secret-never-deployed",
                "syntheticlearnerclient1", null, DOMAIN, Duration.ofSeconds(3), Duration.ofSeconds(7));
        var http = new GatewayClientConfiguration().gatewayHttp(properties, environment, provider(registry));
        for (String rejected : List.of("https://domain.lookahead-dev.internal:8081/actuator/health/readiness",
                "http://domain.lookahead-dev.internal:8443/api/v1/auth/me", "https://domain.lookahead-dev.internal/api/v1/auth/me",
                "https://web.lookahead-dev.internal:8081/index.html")) {
            assertThatThrownBy(() -> http.get().uri(java.net.URI.create(rejected)).retrieve().toBodilessEntity()).as(rejected)
                    .satisfies(error -> assertThat(messages(error)).contains("Exact internal HTTPS origin required"));
        }
    }

    @Test void gatewayRequestsExactlyTheScopesAndClientDomainVerifies() {
        var settings = OAuthSettings.from(devMutualTls());
        var registration = new GatewayClientConfiguration().gatewayClient(settings).findByRegistrationId("lookahead");
        // Domain's CognitoTokenVerifier requires issuer, client_id and these four scopes on every forwarded access token.
        assertThat(registration.getProviderDetails().getIssuerUri()).isEqualTo(ISSUER);
        assertThat(registration.getClientId()).isEqualTo("syntheticlearnerclient1");
        assertThat(registration.getScopes()).contains("aws.cognito.signin.user.admin", "lookahead-dev/account", "lookahead-dev/content", "lookahead-dev/support");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo(ISSUER + "/.well-known/jwks.json");
        // One shared DomainGateway scalar: Gateway sends it as X-LookAhead-Gateway-Secret, Domain compares the exact bytes.
        assertThat(settings.gatewaySecret()).isEqualTo("synthetic-domain-gateway-secret-never-deployed");
        assertThat(settings.toString()).doesNotContain(settings.gatewaySecret());
    }

    private static ObjectProvider<SslBundles> provider(SslBundles bundles) {
        return new ObjectProvider<>() {
            @Override public SslBundles getObject() { return bundles; }
            @Override public SslBundles getObject(Object... args) { return bundles; }
            @Override public SslBundles getIfAvailable() { return bundles; }
            @Override public SslBundles getIfUnique() { return bundles; }
        };
    }

    private static String messages(Throwable error) {
        var text = new StringBuilder();
        for (Throwable current = error; current != null; current = current.getCause()) text.append(current.getMessage()).append('\n');
        return text.toString();
    }
}
