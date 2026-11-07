package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** DLV-971: the owner's "Run the 4-hour jobs now" is forwarded like the delivery plan; a DEV test account never reaches it. */
class SweepsRouteTest {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final GatewayController controller = new GatewayController(new OAuthSettings("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost"), manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
    private static final String run = "/api/v1/sweeps/run";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }

    @Test void theRouteIsExact() {
        assertThat(GatewayController.sweepsRoute("POST", run)).isTrue();
        for (String path : new String[]{run + "/", "/api/v1/sweeps", "/api/v1/sweeps/run/now", "/api/v1/sweeps/Run", "/api/v1/sweep/run", "/api/v1/sweeps/../sweeps/run", ""})
            assertThat(GatewayController.sweepsRoute("POST", path)).as(path).isFalse();
        for (String method : new String[]{"GET", "PUT", "DELETE", "PATCH", "HEAD"})
            assertThat(GatewayController.sweepsRoute(method, run)).as(method).isFalse();
        assertThat(GatewayController.deliveryRoute("POST", run)).isFalse();
        assertThat(GatewayController.platformReviewRoute("POST", run)).isFalse();
    }

    @Test void theRunIsRelayedWithTheServerBearerAndTheDomainAnswerTravelsBack() throws Exception {
        authorize();
        var request = new MockHttpServletRequest("POST", "/bff" + run);
        byte[] body = "{\"job\":\"delivery-inbox\"}".getBytes();
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(body);
        request.addHeader("Cookie", "private=value");
        request.addHeader("Authorization", "Bearer browser-token");
        String answer = "{\"data\":{\"job\":\"delivery-inbox\",\"ranAt\":\"2026-11-06T18:30:00Z\",\"supportRequestsClosed\":null,\"inboxMerged\":true,\"inboxResult\":\"12\",\"admissionsRemoved\":null}}";
        server.expect(requestTo("http://domain" + run)).andExpect(method(HttpMethod.POST))
                .andExpect(header("Content-Type", MediaType.APPLICATION_JSON_VALUE)).andExpect(content().bytes(body))
                .andExpect(header("Authorization", "Bearer server-token")).andExpect(headerDoesNotExist("Cookie"))
                .andRespond(withSuccess(answer, MediaType.APPLICATION_JSON));
        // An admin: the Domain's 403 reaches the browser unchanged; so do the 400 for an unknown job and the 409 of a local Domain.
        server.expect(requestTo("http://domain" + run)).andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.FORBIDDEN).body("{\"code\":\"PLATFORM_REVIEW_ACCESS_DENIED\"}").contentType(MediaType.APPLICATION_JSON));
        server.expect(requestTo("http://domain" + run)).andExpect(method(HttpMethod.POST))
                .andRespond(withStatus(HttpStatus.CONFLICT).body("{\"code\":\"SWEEP_NOT_AVAILABLE\"}").contentType(MediaType.APPLICATION_JSON));
        var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(response.getBody())).isEqualTo(answer);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        var denied = controller.proxy(new MockHttpServletRequest("POST", "/bff" + run), new MockHttpServletResponse(), authentication);
        assertThat(denied.getStatusCode().value()).isEqualTo(403);
        assertThat(new String(denied.getBody())).contains("PLATFORM_REVIEW_ACCESS_DENIED");
        var unavailable = controller.proxy(new MockHttpServletRequest("POST", "/bff" + run), new MockHttpServletResponse(), authentication);
        assertThat(unavailable.getStatusCode().value()).isEqualTo(409);
        assertThat(new String(unavailable.getBody())).contains("SWEEP_NOT_AVAILABLE");
        server.verify();
    }

    @Test void otherMethodsAQueryStringAnOversizedBodyAndAnonymousRequestsStopAtTheGateway() throws Exception {
        authorize();
        assertThat(controller.proxy(new MockHttpServletRequest("GET", "/bff" + run), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(new MockHttpServletRequest("DELETE", "/bff" + run), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        var put = controller.proxy(new MockHttpServletRequest("PUT", "/bff" + run), new MockHttpServletResponse(), authentication);
        assertThat(put.getStatusCode().value()).isEqualTo(405);
        assertThat(put.getHeaders().getCacheControl()).isEqualTo("no-store");
        var query = new MockHttpServletRequest("POST", "/bff" + run);
        query.setQueryString("force=true");
        assertThat(controller.proxy(query, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        var oversized = new MockHttpServletRequest("POST", "/bff" + run);
        oversized.setContent(new byte[16 * 1024 + 1]);
        assertThat(controller.proxy(oversized, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(413);
        assertThat(controller.proxy(new MockHttpServletRequest("POST", "/bff" + run), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        server.verify();
    }

    /** A DEV test session is a learner: the run answers the Previews/Architecture refusal, the Domain is never asked. */
    @Test void aTestSessionIsRefusedAndNeverReachesTheDomain() throws Exception {
        var cloud = new OAuthSettings("https://cognito.example.test", "synthetic", "synthetic", null, "http://domain", "http://localhost",
                "https://managed.example.test", "lookahead", "synthetic-gateway-secret-never-used-outside-fixtures");
        var gateway = new GatewayController(cloud, manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
        var testSession = new TestSessionController.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
        var request = new MockHttpServletRequest("POST", "/bff" + run);
        request.setContent("{}".getBytes());
        var response = gateway.proxy(request, new MockHttpServletResponse(), testSession);
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).isEmpty();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo(AuthorPreviewProxy.empty(401).getHeaders().getCacheControl());
        verifyNoInteractions(manager);
        server.verify();
    }
}
