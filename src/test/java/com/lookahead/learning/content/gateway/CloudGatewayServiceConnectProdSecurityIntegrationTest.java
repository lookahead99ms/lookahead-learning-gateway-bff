package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;
import static org.assertj.core.api.Assertions.assertThat;

/** Same restricted alias and browser security contract under separate PROD provider settings. */
@TestPropertySource(properties = {
        "app.oauth.domain-transport=service-connect-tls",
        "app.oauth.domain-api-upstream=http://domain:8080"
})
class CloudGatewayServiceConnectProdSecurityIntegrationTest extends CloudGatewayProdSecurityIntegrationTest {
    @Test void serviceConnectAliasIsActuallySelected() {
        assertThat(settings.domainApiUpstream()).isEqualTo("http://domain:8080");
    }
}
