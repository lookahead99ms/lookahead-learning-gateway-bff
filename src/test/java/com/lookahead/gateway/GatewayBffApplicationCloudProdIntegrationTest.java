package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

/** Execute the same browser security contract under distinct PROD provider/service wiring. */
@ActiveProfiles({"gateway", "prod"})
@TestPropertySource(
    properties = {
      "app.deployment-environment=prod",
      "app.oauth.frontend=https://prod-learn.example.test",
      "app.oauth.domain-api-upstream=https://prod-domain.example.test",
      "app.oauth.client-id=syntheticprodclient12345",
      "app.oauth.client-secret=synthetic-prod-client-secret-never-used-outside-fixtures",
      "app.cognito.issuer=https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ProdExample",
      "app.cognito.managed-login=https://prod-example.auth.us-west-2.amazoncognito.com",
      "app.cognito.scope-prefix=lookahead-prod",
      "app.cognito.gateway-secret=synthetic-prod-internal-secret-never-used-outside-fixtures"
    })
class GatewayBffApplicationCloudProdIntegrationTest
    extends GatewayBffApplicationCloudIntegrationTest {
  @Test
  void productionFixtureIsActuallySelected() {
    assertThat(context.getEnvironment().getProperty("app.deployment-environment"))
        .isEqualTo("prod");
    assertThat(oauth.frontend()).isEqualTo("https://prod-learn.example.test");
    assertThat(oauth.issuer())
        .isEqualTo("https://cognito-idp.us-west-2.amazonaws.com/us-west-2_ProdExample");
    assertThat(oauth.scopePrefix()).isEqualTo("lookahead-prod");
  }
}
