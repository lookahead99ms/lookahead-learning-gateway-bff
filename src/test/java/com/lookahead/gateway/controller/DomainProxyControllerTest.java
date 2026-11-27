package com.lookahead.gateway.controller;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.proxy.DomainProxy;
import com.lookahead.gateway.proxy.DomainProxyRoutes;
import com.lookahead.gateway.proxy.PrivateAnswer;
import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.TestSessionState;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * The Domain relay route ({@code /bff/api/v1/**}, {@code /content/**}) driven through DomainProxyController, one group per
 * kind of route, each with its own set-up. The route predicates are in DomainProxyRoutesTest; the forwarder is driven
 * directly in DomainProxyTest.
 */
class DomainProxyControllerTest {
    @Nested class AuthorReview {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final DomainProxyController controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
    private static final String base = "/bff/api/v1/author/review-artifacts";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }
    private MockHttpServletRequest request(String method, String path) {
        return new MockHttpServletRequest(method, path);
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
            .andRespond(withStatus(HttpStatus.CONFLICT).body("{\"code\":\"STALE_ARTIFACT\"}").contentType(MediaType.APPLICATION_JSON));
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

    /** DLV-971: the delivery plan routes are forwarded like platform reviews; a DEV test account never reaches them. */
    @Nested class Delivery {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final DomainProxyController controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
    private static final String plan = "/api/v1/delivery/plan", items = plan + "/work-items";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
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
                .andRespond(withStatus(HttpStatus.CONFLICT).body("{\"code\":\"CONFLICT\"}").contentType(MediaType.APPLICATION_JSON));
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

    @Test void inboxWritesKeepTheDeliveryAuthenticationAndForwardingBoundaries() throws Exception {
        authorize();
        String[][] routes = {{"PUT", plan + "/inbox"}, {"POST", plan + "/inbox/sync"}};
        byte[] body = "{\"workItems\":[]}".getBytes(StandardCharsets.UTF_8);
        for (String[] route : routes) {
            server.expect(requestTo("http://domain" + route[1])).andExpect(method(HttpMethod.valueOf(route[0])))
                    .andExpect(header("Authorization", "Bearer server-token"))
                    .andExpect(headerDoesNotExist("Cookie")).andExpect(content().bytes(body))
                    .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        }
        for (String[] route : routes) {
            var request = new MockHttpServletRequest(route[0], "/bff" + route[1]);
            request.setContentType(MediaType.APPLICATION_JSON_VALUE);
            request.setContent(body);
            request.addHeader("Authorization", "Bearer browser-token");
            request.addHeader("Cookie", "private=value");
            assertThat(controller.proxy(request, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(200);
            assertThat(controller.proxy(request, new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
            request.setQueryString("force=true");
            assertThat(controller.proxy(request, new MockHttpServletResponse(), authentication).getStatusCode().value())
                    .isEqualTo(route[0].equals("PUT") ? 405 : 404);
            request.setQueryString(null);
            request.setContent(new byte[8 * 1024 * 1024 + 1]);
            assertThat(controller.proxy(request, new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(413);
        }
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
        var cloud = new OAuthClientDetails("https://cognito.example.test", "synthetic", "synthetic", null, "http://domain", "http://localhost",
                "https://managed.example.test", "lookahead", "synthetic-gateway-secret-never-used-outside-fixtures");
        var cloudController = new DomainProxyController(new DomainProxy(cloud, new SignInTokenClient(manager), builder.build()));
        var testSession = new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
        String review = "/api/v1/platform-reviews/6c8bc359-1141-4c98-83e6-a5ca967fe180";
        for (String[] call : new String[][]{{"GET", plan}, {"POST", items}, {"PUT", items + "/DLV-971"}, {"POST", items + "/DLV-971/resolve-conflict"}, {"PUT", plan + "/inbox"}, {"POST", plan + "/inbox/sync"}, {"POST", review + "/promote"}}) {
            var request = new MockHttpServletRequest(call[0], "/bff" + call[1]);
            request.setContent("{}".getBytes());
            var response = cloudController.proxy(request, new MockHttpServletResponse(), testSession);
            assertThat(response.getStatusCode().value()).as(call[0] + " " + call[1]).isEqualTo(401);
            assertThat(response.getBody()).as(call[0] + " " + call[1]).isEmpty();
            assertThat(response.getHeaders().getCacheControl()).isEqualTo(PrivateAnswer.empty(401).getHeaders().getCacheControl());
        }
        verifyNoInteractions(manager);
        server.verify();
        // The same test session, with its gate admission, still reads its own platform reviews through the Domain.
        var request = new MockHttpServletRequest("GET", "/bff/api/v1/platform-reviews/me");
        request.setSession(new MockHttpSession());
        request.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("admin@example.test", "sub-admin", Instant.now()));
        server.expect(requestTo("http://domain/api/v1/platform-reviews/me")).andExpect(method(HttpMethod.GET))
                .andExpect(header(TestSessionState.ACCOUNT_HEADER, "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a")).andExpect(headerDoesNotExist("Authorization"))
                .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
        assertThat(cloudController.proxy(request, new MockHttpServletResponse(), testSession).getStatusCode().value()).isEqualTo(200);
        server.verify();
    }
    }

    @Nested class PlatformReview {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final DomainProxyController controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
    private static final String root = "/api/v1/platform-reviews";
    private static final String id = "6c8bc359-1141-4c98-83e6-a5ca967fe180";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
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
                .andRespond(withStatus(HttpStatus.CREATED).body("{\"data\":{}}").contentType(MediaType.APPLICATION_JSON));
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
        oversized.setContent(new byte[DomainProxyRoutes.PLATFORM_REVIEW_BODY_BYTES + 1]);
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

    /** DLV-971: the owner's "Run the 4-hour jobs now" is forwarded like the delivery plan; a DEV test account never reaches it. */
    @Nested class Sweeps {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final DomainProxyController controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
    private static final String run = "/api/v1/sweeps/run";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
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
        var cloud = new OAuthClientDetails("https://cognito.example.test", "synthetic", "synthetic", null, "http://domain", "http://localhost",
                "https://managed.example.test", "lookahead", "synthetic-gateway-secret-never-used-outside-fixtures");
        var cloudController = new DomainProxyController(new DomainProxy(cloud, new SignInTokenClient(manager), builder.build()));
        var testSession = new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
        var request = new MockHttpServletRequest("POST", "/bff" + run);
        request.setContent("{}".getBytes());
        var response = cloudController.proxy(request, new MockHttpServletResponse(), testSession);
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).isEmpty();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo(PrivateAnswer.empty(401).getHeaders().getCacheControl());
        verifyNoInteractions(manager);
        server.verify();
    }
    }

    /** DLV-969: the owner's waiting list and admit call are staff-access routes; no other /admin/access path is forwarded. */
    @Nested class StaffAccess {
    static final String UPSTREAM = DomainContractTest.UPSTREAM;
    final DefaultOAuth2User user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "owner"), "sub");
    final OAuth2AuthenticationToken owner = new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");

    DomainProxyController controller(RestClient.Builder builder) {
        var registration = new OAuthClientConfiguration().oauthClientRegistrations(DomainContractTest.LOCAL).findByRegistrationId("lookahead");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, owner.getName(),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "synthetic-server-held-token", Instant.now(), Instant.now().plusSeconds(600))));
        return new DomainProxyController(new DomainProxy(DomainContractTest.LOCAL, new SignInTokenClient(manager), builder.build()));
    }
    static MockHttpServletRequest json(String method, String path, String body) {
        var request = new MockHttpServletRequest(method, path);
        request.setContentType(MediaType.APPLICATION_JSON_VALUE); request.setContent(body.getBytes(StandardCharsets.UTF_8));
        return request;
    }

    @Test void waitingListAndAdmitAreForwardedUnchangedWithTheServerHeldToken() throws Exception {
        var builder = RestClient.builder(); var domain = MockRestServiceServer.bindTo(builder).build();
        domain.expect(requestTo(UPSTREAM + "/api/v1/admin/access/waiting")).andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer synthetic-server-held-token")).andExpect(headerDoesNotExist("Cookie"))
                .andRespond(withSuccess("{\"data\":{\"waiting\":[],\"expiryHours\":48}}", MediaType.APPLICATION_JSON));
        domain.expect(requestTo(UPSTREAM + "/api/v1/admin/access/admit")).andExpect(method(HttpMethod.POST))
                .andExpect(header("Authorization", "Bearer synthetic-server-held-token"))
                .andExpect(content().json("{\"accountId\":\"7d3f2c1a-0000-4000-8000-000000000001\",\"roles\":[\"tester\"]}"))
                .andRespond(withSuccess("{\"data\":{\"accountId\":\"7d3f2c1a-0000-4000-8000-000000000001\",\"roles\":[\"tester\"]}}", MediaType.APPLICATION_JSON));
        var controller = controller(builder);
        var waiting = new MockHttpServletRequest("GET", "/bff/api/v1/admin/access/waiting"); waiting.addHeader("Cookie", "SESSION=private");
        var listed = controller.proxy(waiting, new MockHttpServletResponse(), owner);
        assertThat(listed.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(listed.getBody(), StandardCharsets.UTF_8)).contains("\"expiryHours\":48");
        assertThat(listed.getHeaders().getCacheControl()).isEqualTo("no-store");
        var admitted = controller.proxy(json("POST", "/bff/api/v1/admin/access/admit", "{\"accountId\":\"7d3f2c1a-0000-4000-8000-000000000001\",\"roles\":[\"tester\"]}"),
                new MockHttpServletResponse(), owner);
        assertThat(admitted.getStatusCode().value()).isEqualTo(200);
        domain.verify();
    }

    @Test void theStaffAccessRulesApplyAndNothingElseUnderAdminAccessIsForwarded() throws Exception {
        var builder = RestClient.builder(); var domain = MockRestServiceServer.bindTo(builder).build();
        var controller = controller(builder);
        for (String[] attempt : new String[][]{{"GET", "/bff/api/v1/admin/access/other"}, {"GET", "/bff/api/v1/admin/access/admit"},
                {"POST", "/bff/api/v1/admin/access/waiting"}, {"DELETE", "/bff/api/v1/admin/access/waiting"}, {"GET", "/bff/api/v1/admin/access/waiting/all"}})
            assertThat(controller.proxy(json(attempt[0], attempt[1], "{}"), new MockHttpServletResponse(), owner).getStatusCode().value()).as(String.join(" ", attempt)).isEqualTo(404);
        var filtered = new MockHttpServletRequest("GET", "/bff/api/v1/admin/access/waiting"); filtered.setQueryString("expired=true");
        assertThat(controller.proxy(filtered, new MockHttpServletResponse(), owner).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(new MockHttpServletRequest("GET", "/bff/api/v1/admin/access/waiting"), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        assertThat(controller.proxy(json("POST", "/bff/api/v1/admin/access/admit", "{}"), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(401);
        var oversized = new MockHttpServletRequest("POST", "/bff/api/v1/admin/access/admit");
        oversized.setContentType(MediaType.APPLICATION_JSON_VALUE); oversized.setContent(new byte[16 * 1024 + 1]);
        assertThat(controller.proxy(oversized, new MockHttpServletResponse(), owner).getStatusCode().value()).isEqualTo(413);
        domain.verify();
    }
    }

    @Nested class InvitationActivation {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final DomainProxyController controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
    private static final String base = "/bff/api/v1/auth/invitations/activate";

    private void authorize() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
    }
    private MockHttpServletRequest request(String method, String path) {
        return new MockHttpServletRequest(method, path);
    }
    @Test void onlyPostWithoutQueryReachesDomainUsingServerBearer() throws Exception {
        for(String method : new String[]{"GET", "DELETE"})
            assertThat(controller.proxy(request(method,base),new MockHttpServletResponse(),authentication).getStatusCode().value()).isEqualTo(404);
        var query=request("POST",base);query.setQueryString("email=other@example.invalid");
        assertThat(controller.proxy(query,new MockHttpServletResponse(),authentication).getStatusCode().value()).isEqualTo(404);
        assertThat(controller.proxy(request("POST",base),new MockHttpServletResponse(),null).getStatusCode().value()).isEqualTo(401);
        verifyNoInteractions(manager);
        authorize();
        var request=request("POST",base);
        request.addHeader("Authorization","Bearer browser-token");request.addHeader("Cookie","private=value");
        server.expect(requestTo("http://domain/api/v1/auth/invitations/activate"))
            .andExpect(method(HttpMethod.POST)).andExpect(header("Authorization","Bearer server-token"))
            .andExpect(headerDoesNotExist("Cookie"))
            .andRespond(withSuccess("{\"data\":{\"accountId\":\"synthetic\"}}",MediaType.APPLICATION_JSON));
        assertThat(controller.proxy(request,new MockHttpServletResponse(),authentication).getStatusCode().value()).isEqualTo(200);
        server.verify();
    }
    @Test void directoryForwardsEncodedQueryOnlyOnAuthenticatedGet() throws Exception {
        String path="/bff/api/v1/admin/accounts";
        var request=request("GET",path);request.setQueryString("query=real%2Bname&page=2");
        assertThat(controller.proxy(request,new MockHttpServletResponse(),null).getStatusCode().value()).isEqualTo(401);
        for(String method:new String[]{"POST","DELETE"})assertThat(controller.proxy(request(method,path),new MockHttpServletResponse(),authentication).getStatusCode().value()).isEqualTo(404);
        authorize();request.addHeader("Cookie","private=value");request.addHeader("Authorization","Bearer untrusted");
        server.expect(requestTo("http://domain/api/v1/admin/accounts?query=real%2Bname&page=2"))
            .andExpect(method(HttpMethod.GET)).andExpect(header("Authorization","Bearer server-token"))
            .andExpect(headerDoesNotExist("Cookie")).andRespond(withSuccess("{\"data\":{\"accounts\":[],\"page\":2,\"hasNext\":false}}",MediaType.APPLICATION_JSON));
        assertThat(controller.proxy(request,new MockHttpServletResponse(),authentication).getStatusCode().value()).isEqualTo(200);server.verify();
    }
    }

    /** The account projection of the Domain passes through unchanged (from the JSON wire-contract test). */
    @Nested class JsonContract {
    private static final Instant TIMESTAMP = Instant.parse("2026-09-18T00:00:00Z");
    private static final String ACCESS_TOKEN = "synthetic-server-held-access-token";
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://127.0.0.1:4331", "lookahead-json-contract",
            "synthetic-client-secret-for-json-contract", "http://identity:8080", "http://domain-api:8080",
            "http://127.0.0.1:4331");

    @Test void domainAccountProjectionPassesOldNewAndNullFieldsWithoutRewritingOrCredentialHeaders() throws Exception {
        var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "synthetic-user"), "sub");
        var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");
        var registration = new OAuthClientConfiguration().oauthClientRegistrations(oauth).findByRegistrationId("lookahead");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, authentication.getName(),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN, TIMESTAMP, TIMESTAMP.plusSeconds(3600))));
        for (String payload : List.of(
                "{\"data\":{\"accountId\":\"aaaabbbb-cccc-dddd-eeee-ffffffffffff\",\"username\":\"learner@example.test\",\"displayName\":null,\"topicGrants\":[\"learn:core-java\"]},\"timestamp\":\"2026-09-18T00:00:00Z\"}",
                "{\"data\":{\"accountId\":\"aaaabbbb-cccc-dddd-eeee-ffffffffffff\",\"username\":\"learner@example.test\",\"displayName\":\"Learner\",\"topicGrants\":[],\"contentGrants\":[],\"authorPreview\":false,\"futureOptionalField\":null},\"timestamp\":\"2026-09-18T00:00:00Z\"}",
                "{\"data\":null,\"timestamp\":\"2026-09-18T00:00:00Z\"}")) {
            var builder = RestClient.builder();
            var upstream = MockRestServiceServer.bindTo(builder).build();
            var controller = new DomainProxyController(new DomainProxy(oauth, new SignInTokenClient(manager), builder.build()));
            upstream.expect(requestTo("http://domain-api:8080/api/v1/auth/me"))
                    .andExpect(header("Authorization", "Bearer " + ACCESS_TOKEN))
                    .andExpect(headerDoesNotExist("Cookie"))
                    .andRespond(withSuccess(payload, MediaType.APPLICATION_JSON)
                            .header("Authorization", "Bearer " + ACCESS_TOKEN)
                            .header("Set-Cookie", "UPSTREAM_SESSION=synthetic"));
            var request = new MockHttpServletRequest("GET", "/bff/api/v1/auth/me");
            request.addHeader("Authorization", "Bearer browser-controlled");
            request.addHeader("Cookie", "LOOKAHEAD_GATEWAY=synthetic-browser-session");
            var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(response.getBody()).isEqualTo(payload.getBytes(StandardCharsets.UTF_8));
            assertThat(response.getHeaders().get("Authorization")).isNull();
            assertThat(response.getHeaders().get("Set-Cookie")).isNull();
            assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).doesNotContain(ACCESS_TOKEN, oauth.clientSecret());
            upstream.verify();
        }
    }
    }
}
