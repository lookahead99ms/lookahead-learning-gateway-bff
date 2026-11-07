package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Instant;
import java.util.UUID;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class PlatformReviewGatewayTest {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final GatewayController controller = new GatewayController(new OAuthSettings("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost"), manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
    private static final String root = "/api/v1/platform-reviews";
    private static final String id = "6c8bc359-1141-4c98-83e6-a5ca967fe180";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }

    @Test void routesAreExact() {
        for (String path : new String[]{root, root + "/me", root + "/" + id, root + "/" + id + "/attachments/" + id})
            assertThat(GatewayController.platformReviewRoute("GET", path)).isTrue();
        assertThat(GatewayController.platformReviewRoute("POST", root)).isTrue();
        // DLV-971: promoting a review onto the delivery plan is a POST on the exact lowercase-UUID item.
        assertThat(GatewayController.platformReviewRoute("POST", root + "/" + id + "/promote")).isTrue();
        assertThat(GatewayController.promoteRoute("POST", root + "/" + id + "/promote")).isTrue();
        for (String path : new String[]{root + "/" + id.toUpperCase() + "/promote", root + "/promote", root + "/" + id + "/promote/", root + "/" + id + "/promoted"}) {
            assertThat(GatewayController.platformReviewRoute("POST", path)).as(path).isFalse();
            assertThat(GatewayController.promoteRoute("POST", path)).as(path).isFalse();
        }
        for (String method : new String[]{"GET", "PUT", "DELETE"}) {
            assertThat(GatewayController.platformReviewRoute(method, root + "/" + id + "/promote")).as(method).isFalse();
            assertThat(GatewayController.promoteRoute(method, root + "/" + id + "/promote")).as(method).isFalse();
        }
        assertThat(GatewayController.platformReviewRoute("PUT", root + "/" + id)).isTrue();
        assertThat(GatewayController.platformReviewRoute("PUT", root + "/" + id + "/triage")).isTrue();
        assertThat(GatewayController.platformReviewRoute("DELETE", root + "/" + id)).isTrue();
        for (String path : new String[]{root + "/", root + "/" + id.toUpperCase(), root + "/../plans", root + "/" + id + "/attachments",
                root + "/" + id + "/attachments/" + id + "/x", root + "/me/x", root + "/%2e%2e"})
            assertThat(GatewayController.platformReviewRoute("GET", path)).isFalse();
        assertThat(GatewayController.platformReviewRoute("POST", root + "/" + id)).isFalse();
        assertThat(GatewayController.platformReviewRoute("DELETE", root)).isFalse();
        assertThat(GatewayController.platformReviewRoute("PATCH", root + "/" + id)).isFalse();
        // DLV-971 (owner, 2026-11-06): the runtime record stores number their items; the same routes accept REV-000001 and SUP-000001.
        for (String record : new String[]{"REV-000001", "SUP-000014", "REV-1234567"}) {
            for (String path : new String[]{root + "/" + record, root + "/" + record + "/attachments/" + id})
                assertThat(GatewayController.platformReviewRoute("GET", path)).as(path).isTrue();
            assertThat(GatewayController.platformReviewRoute("PUT", root + "/" + record)).as(record).isTrue();
            assertThat(GatewayController.platformReviewRoute("PUT", root + "/" + record + "/triage")).as(record).isTrue();
            assertThat(GatewayController.platformReviewRoute("DELETE", root + "/" + record)).as(record).isTrue();
            assertThat(GatewayController.promoteRoute("POST", root + "/" + record + "/promote")).as(record).isTrue();
        }
        for (String bad : new String[]{"REV-00001", "rev-000001", "SUP-000001x", "DLV-000001", "REV-000001/attachments/REV-000001"})
            assertThat(GatewayController.platformReviewRoute("GET", root + "/" + bad)).as(bad).isFalse();
    }

    @Test void uploadIsRelayedUnchangedWithIdempotencyKeyAndServerBearer() throws Exception {
        authorize();
        var request = new MockHttpServletRequest("POST", "/bff" + root);
        String type = "multipart/form-data; boundary=synthetic";
        byte[] body = "--synthetic\r\nContent-Disposition: form-data; name=\"item\"; filename=\"blob\"\r\n\r\n{}\r\n--synthetic--\r\n".getBytes();
        request.setContentType(type);
        request.setContent(body);
        String key = UUID.randomUUID().toString();
        request.addHeader("Idempotency-Key", key);
        request.addHeader("Cookie", "private=value");
        server.expect(requestTo("http://domain" + root)).andExpect(method(HttpMethod.POST))
                .andExpect(header("Content-Type", type)).andExpect(header("Idempotency-Key", key))
                .andExpect(header("Authorization", "Bearer server-token")).andExpect(headerDoesNotExist("Cookie"))
                .andExpect(content().bytes(body))
                .andRespond(withStatus(org.springframework.http.HttpStatus.CREATED).body("{\"data\":{}}").contentType(MediaType.APPLICATION_JSON));
        assertThat(controller.proxy(request, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(201);
        server.verify();
    }

    @Test void imagesComeBackWithTheirTypeAndNoStore() throws Exception {
        authorize();
        server.expect(requestTo("http://domain" + root + "/" + id + "/attachments/" + id)).andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(new byte[]{(byte) 0x89, 'P', 'N', 'G'}, MediaType.IMAGE_PNG));
        var response = controller.proxy(new MockHttpServletRequest("GET", "/bff" + root + "/" + id + "/attachments/" + id), new MockHttpServletResponse(), authentication);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.IMAGE_PNG);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        server.verify();
    }

    @Test void limitsMethodsAndAnonymousRequestsStopAtTheGateway() throws Exception {
        var oversized = new MockHttpServletRequest("POST", "/bff" + root);
        oversized.setContent(new byte[GatewayController.PLATFORM_REVIEW_BODY_BYTES + 1]);
        assertThat(controller.proxy(oversized, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(413);
        var plans = new MockHttpServletRequest("PUT", "/bff/api/v1/plans");
        assertThat(controller.proxy(plans, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(405);
        var query = new MockHttpServletRequest("POST", "/bff" + root);
        query.setQueryString("reviewer=other");
        assertThat(controller.proxy(query, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(new MockHttpServletRequest("GET", "/bff" + root), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(manager);
        server.verify();
    }
}
