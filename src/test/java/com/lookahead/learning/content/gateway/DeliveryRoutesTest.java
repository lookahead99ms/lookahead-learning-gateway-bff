package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Instant;
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

/** DLV-971: the delivery plan routes are forwarded like platform reviews; a DEV test account never reaches them. */
class DeliveryRoutesTest {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final GatewayController controller = new GatewayController(new OAuthSettings("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost"), manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
    private static final String plan = "/api/v1/delivery/plan", items = plan + "/work-items";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }

    @Test void routesAreExact() {
        assertThat(GatewayController.deliveryRoute("GET", plan)).isTrue();
        assertThat(GatewayController.deliveryRoute("POST", items)).isTrue();
        for (String id : new String[]{"DLV-971", "a", "9", "DLV-971.2_b", "A".repeat(80), "x-".repeat(40)}) {
            assertThat(GatewayController.deliveryRoute("PUT", items + "/" + id)).as(id).isTrue();
            assertThat(GatewayController.deliveryRoute("POST", items + "/" + id + "/resolve-conflict")).as(id).isTrue();
        }
        // Malformed ids: a leading dot, underscore or hyphen, 81 characters, a slash, a space, an encoded dot, nothing at all.
        for (String id : new String[]{".DLV-971", "_x", "-x", "A".repeat(81), "DLV/971", "DLV 971", "%2e%2e", "", "DLV-971/"}) {
            assertThat(GatewayController.deliveryRoute("PUT", items + "/" + id)).as(id).isFalse();
            assertThat(GatewayController.deliveryRoute("POST", items + "/" + id + "/resolve-conflict")).as(id).isFalse();
        }
        for (String path : new String[]{plan + "/", items, "/api/v1/delivery", "/api/v1/delivery/plans", plan + "/../plans", items + "/DLV-971", items + "/DLV-971/resolve-conflict"})
            assertThat(GatewayController.deliveryRoute("GET", path)).as(path).isFalse();
        for (String path : new String[]{plan, items + "/", items + "/DLV-971", items + "/DLV-971/resolve-conflict/", items + "/DLV-971/resolve", items + "/DLV-971/promote"})
            assertThat(GatewayController.deliveryRoute("POST", path)).as(path).isFalse();
        for (String path : new String[]{plan, items, items + "/DLV-971/resolve-conflict"})
            assertThat(GatewayController.deliveryRoute("PUT", path)).as(path).isFalse();
        // The plan inbox (owner, 2026-11-07): PUT the file, POST the sync; nothing else under /inbox.
        assertThat(GatewayController.deliveryRoute("PUT", plan + "/inbox")).isTrue();
        assertThat(GatewayController.deliveryRoute("POST", plan + "/inbox/sync")).isTrue();
        for (String path : new String[]{plan + "/inbox/", plan + "/inbox/sync", plan + "/inbox/plan.json", plan + "/inbox/../plan"})
            assertThat(GatewayController.deliveryRoute("PUT", path)).as(path).isFalse();
        for (String path : new String[]{plan + "/inbox", plan + "/inbox/sync/", plan + "/inbox/merge", plan + "/inbox/sync/now"})
            assertThat(GatewayController.deliveryRoute("POST", path)).as(path).isFalse();
        for (String path : new String[]{plan + "/inbox", plan + "/inbox/sync"}) {
            assertThat(GatewayController.deliveryRoute("GET", path)).as(path).isFalse();
            assertThat(GatewayController.deliveryRoute("DELETE", path)).as(path).isFalse();
        }
        for (String path : new String[]{plan, items, items + "/DLV-971", items + "/DLV-971/resolve-conflict"}) {
            assertThat(GatewayController.deliveryRoute("DELETE", path)).as(path).isFalse();
            assertThat(GatewayController.deliveryRoute("PATCH", path)).as(path).isFalse();
        }
    }

    @Test void writesAreRelayedWithTheServerBearerIfMatchAndNoBrowserHeaders() throws Exception {
        authorize();
        var request = new MockHttpServletRequest("PUT", "/bff" + items + "/DLV-971");
        byte[] body = "{\"title\":\"Delivery routes\"}".getBytes();
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(body);
        request.addHeader("If-Match", "\"3\"");
        request.addHeader("Cookie", "private=value");
        request.addHeader("Authorization", "Bearer browser-token");
        server.expect(requestTo("http://domain" + items + "/DLV-971")).andExpect(method(HttpMethod.PUT))
                .andExpect(header("Content-Type", MediaType.APPLICATION_JSON_VALUE)).andExpect(header("If-Match", "\"3\""))
                .andExpect(header("Authorization", "Bearer server-token")).andExpect(headerDoesNotExist("Cookie"))
                .andExpect(content().bytes(body))
                .andRespond(withSuccess("{\"data\":{\"id\":\"DLV-971\"}}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("http://domain" + items + "/DLV-971/resolve-conflict")).andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer server-token"))
                .andRespond(withStatus(org.springframework.http.HttpStatus.CONFLICT).body("{\"code\":\"CONFLICT\"}").contentType(MediaType.APPLICATION_JSON));
        var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        // The Domain's answer travels back unchanged, a conflict included.
        var conflict = new MockHttpServletRequest("POST", "/bff" + items + "/DLV-971/resolve-conflict");
        conflict.setContentType(MediaType.APPLICATION_JSON_VALUE);
        conflict.setContent("{}".getBytes());
        assertThat(controller.proxy(conflict, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(409);
        server.verify();
    }

    @Test void readsAllowAQueryStringAndWritesDoNot() throws Exception {
        authorize();
        server.expect(requestTo("http://domain" + plan + "?since=2026-11-06")).andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"data\":{\"workItems\":[]}}", MediaType.APPLICATION_JSON));
        var read = new MockHttpServletRequest("GET", "/bff" + plan);
        read.setQueryString("since=2026-11-06");
        assertThat(controller.proxy(read, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(200);
        var write = new MockHttpServletRequest("POST", "/bff" + items);
        write.setQueryString("force=true");
        assertThat(controller.proxy(write, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        server.verify();
    }

    @Test void refusedRoutesAndAnonymousRequestsStopAtTheGateway() throws Exception {
        assertThat(controller.proxy(new MockHttpServletRequest("DELETE", "/bff" + plan), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(new MockHttpServletRequest("DELETE", "/bff" + items + "/DLV-971"), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(new MockHttpServletRequest("GET", "/bff" + items), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        var whole = controller.proxy(new MockHttpServletRequest("PUT", "/bff" + plan), new MockHttpServletResponse(), authentication);
        assertThat(whole.getStatusCode().value()).isEqualTo(405);
        assertThat(whole.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(controller.proxy(new MockHttpServletRequest("PUT", "/bff" + items + "/.DLV-971"), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(405);
        assertThat(controller.proxy(new MockHttpServletRequest("POST", "/bff" + items + "/" + "A".repeat(81) + "/resolve-conflict"), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(404);
        for (String path : new String[]{plan, items, items + "/DLV-971/resolve-conflict"})
            assertThat(controller.proxy(new MockHttpServletRequest(path.equals(plan) ? "GET" : "POST", "/bff" + path), new MockHttpServletResponse(), null).getStatusCode().value()).as(path).isEqualTo(401);
        assertThat(controller.proxy(new MockHttpServletRequest("PUT", "/bff" + items + "/DLV-971"), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(manager);
        server.verify();
    }

    /** A DEV test session is a learner: the plan and promote answer the Previews/Architecture refusal; its other routes still forward. */
    @Test void aTestSessionIsRefusedLikePreviewsAndNeverReachesTheDomain() throws Exception {
        var cloud = new OAuthSettings("https://cognito.example.test", "synthetic", "synthetic", null, "http://domain", "http://localhost",
                "https://managed.example.test", "lookahead", "synthetic-gateway-secret-never-used-outside-fixtures");
        var gateway = new GatewayController(cloud, manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
        var testSession = new TestSessionController.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
        String review = "/api/v1/platform-reviews/6c8bc359-1141-4c98-83e6-a5ca967fe180";
        for (String[] call : new String[][]{{"GET", plan}, {"POST", items}, {"PUT", items + "/DLV-971"}, {"POST", items + "/DLV-971/resolve-conflict"}, {"POST", review + "/promote"}}) {
            var request = new MockHttpServletRequest(call[0], "/bff" + call[1]);
            request.setContent("{}".getBytes());
            var response = gateway.proxy(request, new MockHttpServletResponse(), testSession);
            assertThat(response.getStatusCode().value()).as(call[0] + " " + call[1]).isEqualTo(401);
            assertThat(response.getBody()).as(call[0] + " " + call[1]).isEmpty();
            assertThat(response.getHeaders().getCacheControl()).isEqualTo(AuthorPreviewProxy.empty(401).getHeaders().getCacheControl());
        }
        verifyNoInteractions(manager);
        server.verify();
        // The same test session, with its gate admission, still reads its own platform reviews through the Domain.
        var request = new MockHttpServletRequest("GET", "/bff/api/v1/platform-reviews/me");
        request.setSession(new org.springframework.mock.web.MockHttpSession());
        request.getSession().setAttribute(DevAdmission.ATTRIBUTE, new DevAdmission.State("admin@example.test", "sub-admin", Instant.now()));
        server.expect(requestTo("http://domain/api/v1/platform-reviews/me")).andExpect(method(HttpMethod.GET))
                .andExpect(header(TestSessionController.ACCOUNT_HEADER, "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a")).andExpect(headerDoesNotExist("Authorization"))
                .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
        assertThat(gateway.proxy(request, new MockHttpServletResponse(), testSession).getStatusCode().value()).isEqualTo(200);
        server.verify();
    }
}
