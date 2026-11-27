package com.lookahead.gateway.proxy;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.TestSessionState;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** DLV-1015: the Domain relay driven directly; the routes drive it in the DomainProxyController tests. */
class DomainProxyTest {
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost");
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final RestClient.Builder http = RestClient.builder();
    private final MockRestServiceServer domain = MockRestServiceServer.bindTo(http).build();
    private final DomainProxy proxy = new DomainProxy(oauth, new SignInTokenClient(manager), http.build());

    @Test void aSignedOutRequestIsRelayedWithTheNamedHeadersOnlyAndWithoutAToken() {
        var request = new MockHttpServletRequest("GET", "/bff/api/v1/plans");
        request.setQueryString("page=2");
        request.addHeader("Accept", "application/json");
        request.addHeader("Authorization", "Bearer browser-controlled");
        request.addHeader("Cookie", "LOOKAHEAD_GATEWAY=gateway-session");
        domain.expect(requestTo("http://domain/api/v1/plans?page=2")).andExpect(method(HttpMethod.GET))
                .andExpect(header("Accept", "application/json")).andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("Cookie"))
                .andExpect(headerDoesNotExist(TestSessionState.SECRET_HEADER))
                .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
        var answer = proxy.forward(request, new MockHttpServletResponse(), null, "/api/v1/plans", new byte[0], false, false);
        domain.verify();
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(answer.getBody())).isEqualTo("{\"data\":[]}");
        assertThat(answer.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(answer.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        verifyNoInteractions(manager);
    }

    @Test void aTestSessionWhoseGateAdmissionIsGoneIsRefusedBeforeTheDomainIsAsked() {
        var request = new MockHttpServletRequest("GET", "/bff/api/v1/plans");
        var answer = proxy.forward(request, new MockHttpServletResponse(), new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"),
                "/api/v1/plans", new byte[0], true, false);
        assertThat(answer.getStatusCode().value()).isEqualTo(401);
        domain.verify();
        verifyNoInteractions(manager);
    }

    // DLV-1015: the refusals this application answers itself, moved here from DomainProxyController.proxy in the same order.

    private static final OAuthClientDetails CLOUD = new OAuthClientDetails("https://cognito.example.test", "synthetic", "synthetic", null, "http://domain", "http://localhost",
            "https://managed.example.test", "lookahead", "synthetic-gateway-secret-never-used-outside-fixtures");
    private static final TestSessionState.TestSession TEST_SESSION = new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");

    private static MockHttpServletRequest request(String method, String path, int bytes) {
        var request = new MockHttpServletRequest(method, path);
        request.setContent(new byte[bytes]);
        return request;
    }
    /** How many body bytes the relay took from the request. */
    private static int read(MockHttpServletRequest request) throws Exception {
        return request.getContentAsByteArray().length - request.getInputStream().readAllBytes().length;
    }
    private OAuth2AuthenticationToken signedIn() {
        var client = mock(OAuth2AuthorizedClient.class);
        when(client.getAccessToken()).thenReturn(new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "server-token", Instant.now(), Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
        return mock(OAuth2AuthenticationToken.class);
    }

    @Test void theMethodIsRefusedBeforeTheRouteAndTheRouteBeforeTheCallerAndNoBodyIsReadForAny() throws Exception {
        // PUT on an unknown route, by nobody, with a body over every limit: 405 wins.
        var put = request("PUT", "/bff/api/v1/unknown", 64);
        var refused = proxy.relay(put, new MockHttpServletResponse(), null);
        assertThat(refused.getStatusCode().value()).isEqualTo(405);
        assertThat(refused.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(refused.getBody()).isNull();
        assertThat(read(put)).isZero();
        // An unknown route, by nobody: 404 and not 401.
        var unknown = request("POST", "/bff/api/v1/unknown", 64);
        var notFound = proxy.relay(unknown, new MockHttpServletResponse(), null);
        assertThat(notFound.getStatusCode().value()).isEqualTo(404);
        assertThat(notFound.getHeaders().isEmpty()).isTrue();
        assertThat(read(unknown)).isZero();
        // A staff route, by nobody, with a body over its limit: 401 and not 413.
        var staff = request("POST", "/bff/api/v1/sweeps/run", 16 * 1024 + 1);
        var unauthorised = proxy.relay(staff, new MockHttpServletResponse(), null);
        assertThat(unauthorised.getStatusCode().value()).isEqualTo(401);
        assertThat(unauthorised.getHeaders().isEmpty()).isTrue();
        assertThat(unauthorised.getBody()).isNull();
        assertThat(read(staff)).isZero();
        domain.verify();
        verifyNoInteractions(manager);
    }

    @Test void aBodyOverTheRoutesLimitIsRefusedAfterReadingOneByteMoreAndTheExactLimitIsForwarded() throws Exception {
        var authentication = signedIn();
        var large = request("POST", "/bff/api/v1/sweeps/run", 16 * 1024 + 9);
        var tooLarge = proxy.relay(large, new MockHttpServletResponse(), authentication);
        assertThat(tooLarge.getStatusCode().value()).isEqualTo(413);
        assertThat(tooLarge.getHeaders().isEmpty()).isTrue();
        assertThat(read(large)).isEqualTo(16 * 1024 + 1);
        domain.verify();
        verifyNoInteractions(manager);
        domain.expect(requestTo("http://domain/api/v1/sweeps/run")).andExpect(method(HttpMethod.POST)).andExpect(content().bytes(new byte[16 * 1024]))
                .andExpect(header("Authorization", "Bearer server-token")).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(proxy.relay(request("POST", "/bff/api/v1/sweeps/run", 16 * 1024), new MockHttpServletResponse(), authentication).getStatusCode().value()).isEqualTo(200);
        domain.verify();
    }

    @Test void anOpenRouteIsForwardedForAnyoneWithTheDomainPathAndTheQueryString() throws Exception {
        var request = request("GET", "/bff/api/v1/plans", 0);
        request.setQueryString("page=2");
        domain.expect(requestTo("http://domain/api/v1/plans?page=2")).andExpect(method(HttpMethod.GET)).andExpect(headerDoesNotExist("Authorization"))
                .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
        var answer = proxy.relay(request, new MockHttpServletResponse(), null);
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(answer.getBody())).isEqualTo("{\"data\":[]}");
        domain.verify();
        verifyNoInteractions(manager);
    }

    @Test void aTestSessionCountsInTheCloudOnlyAndIsRefusedOnStaffWorkWithThePreviewAnswer() throws Exception {
        var cloudHttp = RestClient.builder();
        var cloudDomain = MockRestServiceServer.bindTo(cloudHttp).build();
        var cloud = new DomainProxy(CLOUD, new SignInTokenClient(manager), cloudHttp.build());
        // In the cloud a test session on the delivery plan gets the Previews/Architecture refusal: 401, no-store, empty body.
        var refused = cloud.relay(request("GET", "/bff/api/v1/delivery/plan", 0), new MockHttpServletResponse(), TEST_SESSION);
        assertThat(refused.getStatusCode().value()).isEqualTo(401);
        assertThat(refused.getBody()).isEmpty();
        assertThat(refused.getHeaders().getCacheControl()).isEqualTo(PrivateAnswer.empty(401).getHeaders().getCacheControl());
        // Its other staff-only routes pass the caller check (the test session stands in for the sign-in); without the gate
        // admission the forwarding step then answers 401 without asking the Domain.
        assertThat(cloud.relay(request("GET", "/bff/api/v1/platform-reviews/me", 0), new MockHttpServletResponse(), TEST_SESSION).getStatusCode().value()).isEqualTo(401);
        cloudDomain.verify();
        // Locally the same authentication is no test session: the staff-only route answers the plain 401 (no headers, no body) ...
        var local = proxy.relay(request("GET", "/bff/api/v1/delivery/plan", 0), new MockHttpServletResponse(), TEST_SESSION);
        assertThat(local.getStatusCode().value()).isEqualTo(401);
        assertThat(local.getHeaders().isEmpty()).isTrue();
        assertThat(local.getBody()).isNull();
        // ... and an open route is forwarded without the test-session headers.
        domain.expect(requestTo("http://domain/api/v1/plans")).andExpect(headerDoesNotExist(TestSessionState.SECRET_HEADER))
                .andExpect(headerDoesNotExist(TestSessionState.ACCOUNT_HEADER)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(proxy.relay(request("GET", "/bff/api/v1/plans", 0), new MockHttpServletResponse(), TEST_SESSION).getStatusCode().value()).isEqualTo(200);
        domain.verify();
        verifyNoInteractions(manager);
    }

    @Test void anExecutionRouteKeepsItsOwnAnswerLimit() throws Exception {
        domain.expect(requestTo("http://domain/api/v1/executions/capabilities")).andRespond(withSuccess(new byte[512 * 1024 + 1], MediaType.APPLICATION_JSON));
        assertThat(proxy.relay(request("GET", "/bff/api/v1/executions/capabilities", 0), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(502);
        domain.verify(); domain.reset();
        domain.expect(requestTo("http://domain/api/v1/plans")).andRespond(withSuccess(new byte[512 * 1024 + 1], MediaType.APPLICATION_JSON));
        assertThat(proxy.relay(request("GET", "/bff/api/v1/plans", 0), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(200);
        domain.verify();
    }
}
