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
        assertThat(OAuthSettings.from(production()).issuer()).isEqualTo("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example");
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("server.servlet.session.cookie.secure", "false")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("server.servlet.session.cookie.name", "LOOKAHEAD_SESSION")));
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(production().withProperty("app.oauth.domain-api-upstream", "http://domain-api:8080")));
    }
    @Test void cloudCredentialsRequireInjectedValuesInDevAndProd() {
        for (String mode : new String[]{"dev", "prod"}) {
            for (String property : new String[]{"app.cognito.gateway-secret", "app.oauth.client-secret"}) {
                for (String invalid : new String[]{"arn:aws:secretsmanager:us-east-2:000000000000:secret:example",
                        "${LOOKAHEAD_UNRESOLVED_SECRET_PLACEHOLDER}", "@application.veryLongSecretReference",
                        "{{resolve:secretsmanager:example-secret-value}}", "x".repeat(33) + "\n",
                        "x".repeat(33) + " ", "x".repeat(4097), "short"}) {
                    assertThatExceptionOfType(RuntimeException.class).isThrownBy(() -> OAuthSettings.from(production()
                            .withProperty("app.deployment-environment", mode).withProperty(property, invalid)));
                }
            }
            assertThat(OAuthSettings.from(production().withProperty("app.deployment-environment", mode)).cloud()).isTrue();
        }
    }
    MockEnvironment production() {
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
}
