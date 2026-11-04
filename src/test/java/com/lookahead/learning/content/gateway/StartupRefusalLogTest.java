package com.lookahead.learning.content.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.LogCapture;
import com.lookahead.learning.content.oauth.DevServiceOrigins;
import com.lookahead.learning.content.oauth.OAuthSettings;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

/** DLV-969 (owner, 2026-11-04): a refused start names the setting and why, never its value; the exception is unchanged. */
class StartupRefusalLogTest {
    final LogCapture log = new LogCapture("lookahead.lifecycle");
    final GatewayDeploymentTest fixtures = new GatewayDeploymentTest();

    @AfterEach void close() { log.close(); }

    void refused(MockEnvironment environment, String message, String setting, String reason, String... secrets) {
        log.clear();
        assertThatIllegalStateException().isThrownBy(() -> OAuthSettings.from(environment)).withMessage(message).withNoCause();
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

    @Test void devUpstreamsNameWhichOneAndTheNameItMustHave() {
        log.clear();
        assertThatIllegalStateException().isThrownBy(() -> DevServiceOrigins.of(DevServiceOrigins.DOMAIN, "https://web.attacker.test:8443"))
                .withMessage("Explicit stable DEV Domain and Web upstreams required");
        assertThat(log.last().getFormattedMessage()).startsWith("Startup refused: app.gateway.web-upstream (LOOKAHEAD_WEB_UPSTREAM, expected "
                + "https://web.lookahead-dev.internal:8443) is not allowed in this deployment (NOT_ALLOWED)");
        assertThatIllegalStateException().isThrownBy(() -> DevServiceOrigins.of(null, DevServiceOrigins.WEB));
        assertThat(LogCapture.pairs(log.last())).contains("setting=app.oauth.domain-api-upstream (LOOKAHEAD_DOMAIN_UPSTREAM, expected "
                + "https://domain.lookahead-dev.internal:8443)", "reason=MISSING");
        assertThatIllegalStateException().isThrownBy(() -> DevServiceOrigins.of(DevServiceOrigins.DOMAIN, " "));
        assertThat(LogCapture.pairs(log.last())).contains("reason=MISSING");
        log.assertNothing("attacker");
    }
}
