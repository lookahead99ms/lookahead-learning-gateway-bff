package com.lookahead.learning.content.gateway;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** DLV-969: the owner's waiting list and admit call are staff-access routes; no other /admin/access path is forwarded. */
class StaffAccessRoutesTest {
    static final String UPSTREAM = DomainContractTest.UPSTREAM;
    final DefaultOAuth2User user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "owner"), "sub");
    final OAuth2AuthenticationToken owner = new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");

    GatewayController controller(RestClient.Builder builder) {
        var registration = new GatewayClientConfiguration().gatewayClient(DomainContractTest.LOCAL).findByRegistrationId("lookahead");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, owner.getName(),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "synthetic-server-held-token", Instant.now(), Instant.now().plusSeconds(600))));
        return new GatewayController(DomainContractTest.LOCAL, manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
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
