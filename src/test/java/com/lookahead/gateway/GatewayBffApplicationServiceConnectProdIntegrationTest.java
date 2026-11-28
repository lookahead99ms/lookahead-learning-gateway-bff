package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.test.context.TestPropertySource;

/** Same restricted alias and browser security contract under separate PROD provider settings. */
@TestPropertySource(
    properties = {
      "app.oauth.domain-transport=service-connect-tls",
      "app.oauth.domain-api-upstream=http://domain:8080"
    })
class GatewayBffApplicationServiceConnectProdIntegrationTest
    extends GatewayBffApplicationCloudProdIntegrationTest {
  @Test
  void serviceConnectAliasIsActuallySelected() {
    assertThat(oauth.domainApiUpstream()).isEqualTo("http://domain:8080");
  }
}
