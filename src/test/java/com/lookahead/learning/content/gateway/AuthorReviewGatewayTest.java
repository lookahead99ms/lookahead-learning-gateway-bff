package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import java.time.Instant;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class AuthorReviewGatewayTest {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final GatewayController controller = new GatewayController(new OAuthSettings("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost"), manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
    private static final String base = "/bff/api/v1/author/review-artifacts";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }
    private MockHttpServletRequest request(String method, String path) {
        return new MockHttpServletRequest(method, path);
    }
    @Test void routesAreExactAndCanonical() {
        assertThat(GatewayController.authorReviewRoute("GET", base.substring(4))).isTrue();
        for (String method : new String[]{"GET", "POST"})
            assertThat(GatewayController.authorReviewRoute(method, base.substring(4) + "/dlv-704/events")).isTrue();
        for (String suffix : new String[]{"/DLV-704/events", "/../events", "/a/events/extra", "/a%2fb/events", "/a/events/", "/" + "a".repeat(81) + "/events", "/a"})
            assertThat(GatewayController.authorReviewRoute("GET", base.substring(4) + suffix)).isFalse();
        assertThat(GatewayController.authorReviewRoute("POST", base.substring(4))).isFalse();
        assertThat(GatewayController.authorReviewRoute("DELETE", base.substring(4) + "/a/events")).isFalse();
    }
    @Test void historyForwardsEncodedCursorAndOnlyServerBearer() throws Exception {
        authorize();
        var request = request("GET", base + "/dlv-704/events");
        request.setQueryString("limit=20&cursor=abc%2Bdef%3D");
        request.addHeader("Authorization", "Bearer browser-token");
        request.addHeader("Cookie", "private=value");
        server.expect(requestTo("http://domain/api/v1/author/review-artifacts/dlv-704/events?limit=20&cursor=abc%2Bdef%3D"))
            .andExpect(method(HttpMethod.GET)).andExpect(header("Authorization", "Bearer server-token"))
            .andExpect(headerDoesNotExist("Cookie")).andRespond(withSuccess("{\"data\":{\"events\":[]}}", MediaType.APPLICATION_JSON));
        var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        server.verify();
    }
    @Test void submitPreservesBodyIdempotencyAndDomainError() throws Exception {
        authorize();
        var request = request("POST", base + "/dlv-704/events");
        request.setContentType("application/json");
        request.setContent("{\"decision\":\"APPROVE\"}".getBytes());
        var key=UUID.randomUUID().toString();
        request.addHeader("Idempotency-Key", key);
        server.expect(requestTo("http://domain/api/v1/author/review-artifacts/dlv-704/events"))
            .andExpect(method(HttpMethod.POST)).andExpect(header("Idempotency-Key", key))
            .andExpect(content().json("{\"decision\":\"APPROVE\"}"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.CONFLICT).body("{\"code\":\"STALE_ARTIFACT\"}").contentType(MediaType.APPLICATION_JSON));
        var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(new String(response.getBody())).contains("STALE_ARTIFACT");
        server.verify();
    }
    @Test void oversizedBodyQueryOnMutationAndAnonymousNeverReachDomain() throws Exception {
        var oversized = request("POST", base + "/dlv-704/events");
        oversized.setContent(new byte[16 * 1024 + 1]);
        assertThat(controller.proxy(oversized, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(413);
        var query = request("POST", base + "/dlv-704/events");
        query.setQueryString("limit=1");
        assertThat(controller.proxy(query, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(request("GET", base), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(manager);
        server.verify();
    }
}
