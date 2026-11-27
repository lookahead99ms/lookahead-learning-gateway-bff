package com.lookahead.gateway.proxy;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/** DLV-1015: the Identity forwarder driven directly; the routes drive it in IdentityProxyControllerTest. */
class IdentityProxyTest {
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-candidate",
            "synthetic-client-secret-for-this-test-only", "http://identity:8080", "http://domain-api:8080",
            "http://127.0.0.1:4350");

    @Test void forwardsTheNamedIdentityCookiesOnlyAndReturnsOnlyThose() throws Exception {
        var http = RestClient.builder();
        var upstream = MockRestServiceServer.bindTo(http).build();
        var proxy = new IdentityProxy(oauth, http.build(), "ID_SESSION", "ID_BINDING", "ID_CHALLENGE", "GATEWAY_SESSION");
        var request = new MockHttpServletRequest("GET", "/api/v1/auth/options");
        request.addHeader("Origin", "http://127.0.0.1:4350");
        request.setCookies(new Cookie("GATEWAY_SESSION", "gateway"), new Cookie("ID_BINDING", "binding"), new Cookie("ID_SESSION", "identity"),
                new Cookie("OTHER", "other"));
        upstream.expect(requestTo("http://identity:8080/api/v1/auth/options")).andExpect(method(HttpMethod.GET))
                .andExpect(header("Cookie", "ID_BINDING=binding; ID_SESSION=identity")).andExpect(header("Origin", "http://127.0.0.1:4350"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON).header("Set-Cookie", "ID_CHALLENGE=next; HttpOnly")
                        .header("Set-Cookie", "GATEWAY_SESSION=unexpected"));
        var response = proxy.forward(request, 1024);
        upstream.verify();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().get("Set-Cookie")).containsExactly("ID_CHALLENGE=next; HttpOnly");
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }

    @Test void refusesCookieNamesThatAreMalformedOrSharedWithTheGatewaySession() {
        var http = RestClient.builder().build();
        assertThatIllegalStateException().isThrownBy(() -> new IdentityProxy(oauth, http, "bad name", "ID_BINDING", "ID_CHALLENGE", "GATEWAY_SESSION"))
                .withMessage("Invalid Identity cookie name");
        assertThatIllegalStateException().isThrownBy(() -> new IdentityProxy(oauth, http, "ID_SESSION", "ID_BINDING", "ID_CHALLENGE", "ID_BINDING"))
                .withMessage("Identity and Gateway cookies must be distinct");
    }
}
