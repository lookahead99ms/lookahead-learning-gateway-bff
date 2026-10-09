package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import static org.assertj.core.api.Assertions.assertThat;

/** Real browser security contract over the exact DEV Service Connect application alias. */
@TestPropertySource(properties = {
        "app.oauth.domain-transport=service-connect-tls",
        "app.oauth.domain-api-upstream=http://domain:8080"
})
class CloudGatewayServiceConnectSecurityIntegrationTest extends CloudGatewaySecurityIntegrationTest {
    @Test void serviceConnectAliasAndDevAreActuallySelected() {
        assertThat(context.getEnvironment().getProperty("app.deployment-environment")).isEqualTo("dev");
        assertThat(settings.domainApiUpstream()).isEqualTo("http://domain:8080");
    }
}
