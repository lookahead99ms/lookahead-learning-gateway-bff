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
 * DLV-914: the bindings Domain's DEV activation contract (docs/dev-activation.md) expects from the Gateway.
 * Slot-specific Domain DNS on application mTLS 8443; Domain's loopback 8081 is readiness only, never an upstream;
 * the same application issuer, client and scopes Domain verifies; one DomainGateway secret binding.
 */
class DomainIntegrationBindingsTest {
    static final String ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example";

    MockEnvironment devMutualTls(String slot) {
        var environment = new MockEnvironment()
                .withProperty("app.deployment-environment", "dev")
                .withProperty("app.oauth.domain-transport", "application-mtls")
                .withProperty("app.oauth.frontend", "https://dev.example.test")
                .withProperty("app.oauth.domain-api-upstream", "https://domain-" + slot + ".lookahead-dev.internal:8443")
                .withProperty("app.oauth.client-id", "syntheticlearnerclient1")
                .withProperty("app.oauth.client-secret", "synthetic-learner-client-secret-never-deployed")
                .withProperty("app.cognito.issuer", ISSUER)
                .withProperty("app.cognito.managed-login", "https://dev-example.auth.us-east-2.amazoncognito.com")
                .withProperty("app.cognito.scope-prefix", "lookahead-dev")
                .withProperty("app.cognito.gateway-secret", "synthetic-domain-gateway-secret-never-deployed")
                .withProperty("server.ssl.enabled", "true").withProperty("server.ssl.bundle", "serving")
                .withProperty("LOOKAHEAD_RELEASE_SLOT", slot);
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        return environment;
    }

    @ParameterizedTest @ValueSource(strings = {"blue", "green"})
    void domainUpstreamIsTheSlotDnsNameOnApplicationMutualTls8443(String slot) {
        var settings = OAuthSettings.from(devMutualTls(slot));
        assertThat(settings.domainApiUpstream()).isEqualTo("https://domain-" + slot + ".lookahead-dev.internal:8443");
        assertThat(DevServiceOrigins.forSlot(slot).domain()).isEqualTo(settings.domainApiUpstream());
        assertThat(DevServiceOrigins.forSlot(slot).web()).isEqualTo("https://web-" + slot + ".lookahead-dev.internal:8443");
        // Domain's 8081 is loopback readiness; the other slot, plaintext and bare hostnames are not Domain upstreams.
        String other = slot.equals("blue") ? "green" : "blue";
        for (String rejected : List.of("https://domain-" + slot + ".lookahead-dev.internal:8081",
                "https://domain-" + slot + ".lookahead-dev.internal", "http://domain-" + slot + ".lookahead-dev.internal:8443",
                "https://domain-" + other + ".lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal:8443",
                "http://domain:8080", "https://domain-" + slot + ".lookahead-dev.internal:8443/api")) {
            var environment = devMutualTls(slot).withProperty("app.oauth.domain-api-upstream", rejected);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(rejected).isInstanceOf(IllegalStateException.class);
        }
        // Application mTLS needs the explicit DEV TLS profile; the Service Connect alias is not accepted in this mode.
        var noTls = devMutualTls(slot).withProperty("server.ssl.enabled", "false");
        assertThatThrownBy(() -> OAuthSettings.from(noTls)).isInstanceOf(IllegalStateException.class);
    }

    @Test void internalClientRefusesDomainReadinessPortAndPlaintextBeforeConnecting() {
        var registry = new DefaultSslBundleRegistry();
        registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
        var environment = devMutualTls("blue");
        var properties = new OAuthProperties(null, "https://dev.example.test", "synthetic-learner-client-secret-never-deployed",
                "syntheticlearnerclient1", null, "https://domain-blue.lookahead-dev.internal:8443", Duration.ofSeconds(3), Duration.ofSeconds(7));
        var http = new GatewayClientConfiguration().gatewayHttp(properties, environment, provider(registry));
        for (String rejected : List.of("https://domain-blue.lookahead-dev.internal:8081/actuator/health/readiness",
                "http://domain-blue.lookahead-dev.internal:8443/api/v1/auth/me", "https://domain-blue.lookahead-dev.internal/api/v1/auth/me",
                "https://web-blue.lookahead-dev.internal:8081/index.html")) {
            assertThatThrownBy(() -> http.get().uri(java.net.URI.create(rejected)).retrieve().toBodilessEntity()).as(rejected)
                    .satisfies(error -> assertThat(messages(error)).contains("Exact internal HTTPS origin required"));
        }
    }

    @Test void gatewayRequestsExactlyTheScopesAndClientDomainVerifies() {
        var settings = OAuthSettings.from(devMutualTls("blue"));
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
