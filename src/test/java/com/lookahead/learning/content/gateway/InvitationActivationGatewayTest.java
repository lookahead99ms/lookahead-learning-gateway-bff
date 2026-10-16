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

class InvitationActivationGatewayTest {
    private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
    private final OAuth2AuthenticationToken authentication = mock(OAuth2AuthenticationToken.class);
    private final RestClient.Builder builder = RestClient.builder();
    private final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    private final GatewayController controller = new GatewayController(new OAuthSettings("http://localhost", "synthetic", "synthetic", "http://identity", "http://domain", "http://localhost"), manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
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
