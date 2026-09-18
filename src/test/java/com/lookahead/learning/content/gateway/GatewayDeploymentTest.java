package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

class GatewayDeploymentTest {
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
        var settings = OAuthSettings.from(environment());
        assertThat(settings.identityUpstream()).isEqualTo("http://identity:8080");
        assertThat(settings.domainApiUpstream()).isEqualTo("http://domain-api:8080");
        // An existing local container may still advertise the historical service name.
        assertThat(OAuthSettings.from(environment().withProperty("app.oauth.domain-api-upstream", "http://platform:8080"))
                .domainApiUpstream()).isEqualTo("http://platform:8080");
        assertThat(settings.toString()).doesNotContain(settings.clientSecret());
        for (String invalid : new String[]{"", "file:///etc/passwd", "http://attacker.test", "http://user@identity:8080", "http://identity:8080/path", "http://identity:8080?x=y"})
            assertThatException().isThrownBy(() -> OAuthSettings.from(environment().withProperty("app.oauth.identity-upstream", invalid)));
    }
    @Test void rejectsAmbiguousEnvironmentAndMixedProfiles() {
        for (String mode : new String[]{"", "production", "development", "unknown"})
            assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(environment().withProperty("app.deployment-environment", mode)));
        // Reject the retired Domain API profile as well as the canonical name.
        for (String role : new String[]{"accounts", "oauth-server", "resource", "domain-api", "platform"}) {
            var mixed = environment(); mixed.setActiveProfiles("gateway", role);
            assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(mixed));
        }
        var localWithProd = environment(); localWithProd.setActiveProfiles("prod");
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(localWithProd));
        var prodWithLocal = production(); prodWithLocal.setActiveProfiles("local");
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(prodWithLocal));
    }
    @Test void productionRequiresHttpsAndSecureDistinctCookie() {
        assertThat(OAuthSettings.from(production()).issuer()).isEqualTo("https://learn.example.test");
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("server.servlet.session.cookie.secure", "false")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("server.servlet.session.cookie.name", "LOOKAHEAD_SESSION")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("app.oauth.domain-api-upstream", "http://domain-api:8080")));
    }
    MockEnvironment production() {
        return environment().withProperty("app.deployment-environment", "prod")
                .withProperty("app.oauth.issuer", "https://learn.example.test")
                .withProperty("app.oauth.frontend", "https://learn.example.test")
                .withProperty("app.oauth.identity-upstream", "https://identity.example.test")
                .withProperty("app.oauth.domain-api-upstream", "https://domain-api.example.test");
    }
}
