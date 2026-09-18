package com.lookahead.learning.content.gateway;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
class ExecutionGatewayRouteTest {
    @Test void onlyExplicitMethodsAndUuidJobRoutesAreAllowed() {
        String job = "/api/v1/executions/jobs/aa852488-aead-4b3d-a91f-c5d189539a52";
        assertThat(GatewayController.executionRoute("GET", job)).isTrue();
        assertThat(GatewayController.executionRoute("DELETE", job)).isTrue();
        assertThat(GatewayController.executionRoute("POST", "/api/v1/executions/jobs")).isTrue();
        assertThat(GatewayController.executionRoute("GET", "/api/v1/executions/capabilities")).isTrue();
        for (String path : new String[]{"/api/v1/executions/jobs", job + "/extra", job + "?url=http://evil", "/api/v1/executions/secrets", "/api/v1/executions/jobs/../../token"}) {
            assertThat(GatewayController.executionRoute("DELETE", path)).isFalse();
        }
        assertThat(GatewayController.executionRoute("POST", job)).isFalse();
    }
}
