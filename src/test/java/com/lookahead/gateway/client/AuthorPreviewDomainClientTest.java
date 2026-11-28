package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.util.AuthorPreviewUpstreamTest;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

/**
 * DLV-1015: the Domain's author-preview access check (moved here from AuthorPreviewProxy.fetch,
 * statement unchanged).
 */
class AuthorPreviewDomainClientTest {
  private final RestClient.Builder http = RestClient.builder();
  private final MockRestServiceServer domain = MockRestServiceServer.bindTo(http).build();

  @Test
  void asksTheDomainWithTheServerHeldTokenAndAnswersItsStatusWhateverItIs() {
    var local = AuthorPreviewUpstreamTest.OAUTH;
    var client = new AuthorPreviewDomainClient(local, http.build());
    for (int status : new int[] {204, 200, 302, 401, 403, 404, 500, 503}) {
      domain.reset();
      domain
          .expect(requestTo(local.domainApiUpstream() + "/api/v1/author/previews/access"))
          .andExpect(method(HttpMethod.GET))
          .andExpect(header("Authorization", "Bearer synthetic-server-token"))
          .andExpect(headerDoesNotExist("Cookie"))
          // Locally no sign-in proof is sent, even when the caller holds one.
          .andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof"))
          .andExpect(headerDoesNotExist("X-LookAhead-Gateway-Secret"))
          .andRespond(withStatus(HttpStatus.valueOf(status)));
      assertThat(client.access("synthetic-server-token", "local-proof"))
          .as("status " + status)
          .isEqualTo(status);
      domain.verify();
    }
  }

  @Test
  void inTheCloudTheSignInProofGoesWithTheTokenWhenThereIsOne() {
    OAuthClientDetails cloud =
        OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    assertThat(cloud.cloud()).isTrue();
    var client = new AuthorPreviewDomainClient(cloud, http.build());
    domain
        .expect(requestTo(cloud.domainApiUpstream() + "/api/v1/author/previews/access"))
        .andExpect(header("Authorization", "Bearer synthetic-server-token"))
        .andExpect(header("X-LookAhead-SignIn-Proof", "session-proof"))
        .andExpect(headerDoesNotExist("X-LookAhead-Gateway-Secret"))
        .andRespond(withStatus(HttpStatus.NO_CONTENT));
    domain
        .expect(requestTo(cloud.domainApiUpstream() + "/api/v1/author/previews/access"))
        .andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof"))
        .andRespond(withStatus(HttpStatus.FORBIDDEN));
    assertThat(client.access("synthetic-server-token", "session-proof")).isEqualTo(204);
    assertThat(client.access("synthetic-server-token", null)).isEqualTo(403);
    domain.verify();
  }

  @Test
  void aDomainThatDoesNotAnswerIsTheCallersToReport() {
    var local = AuthorPreviewUpstreamTest.OAUTH;
    domain
        .expect(requestTo(local.domainApiUpstream() + "/api/v1/author/previews/access"))
        .andRespond(withException(new IOException("synthetic")));
    assertThatThrownBy(() ->
            new AuthorPreviewDomainClient(local, http.build())
                .access("synthetic-server-token", null))
        .isInstanceOf(ResourceAccessException.class);
    domain.verify();
  }
}
