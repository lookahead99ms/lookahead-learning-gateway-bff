package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.http.*;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class IdentityProxyControllerTest {
    private final OAuthSettings settings = new OAuthSettings("http://127.0.0.1:4350", "lookahead-candidate",
            "synthetic-client-secret-for-this-test-only", "http://identity:8080", "http://domain-api:8080",
            "http://127.0.0.1:4350");
    private final RestClient.Builder http = RestClient.builder();
    private final MockRestServiceServer upstream = MockRestServiceServer.bindTo(http).build();
    private final IdentityProxyController proxy = new IdentityProxyController(settings, http.build(), "LOOKAHEAD_SESSION");

    @Test void forwardsOnlyIdentityCookieAndCsrfWithoutGatewayTokenOrCredentials() throws Exception {
        var request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.setContent("username=learner&password=synthetic".getBytes());
        request.addHeader("Content-Type", "application/x-www-form-urlencoded");
        request.addHeader("X-CSRF-TOKEN", "identity-csrf");
        request.addHeader("Authorization", "Bearer browser-controlled");
        request.addHeader("X-Forwarded-Host", "attacker.test");
        request.setCookies(new Cookie("LOOKAHEAD_GATEWAY", "gateway-session"), new Cookie("LOOKAHEAD_SESSION", "identity-session"));
        upstream.expect(requestTo("http://identity:8080/api/v1/auth/login"))
                .andExpect(method(HttpMethod.POST)).andExpect(header("Cookie", "LOOKAHEAD_SESSION=identity-session"))
                .andExpect(header("X-CSRF-TOKEN", "identity-csrf"))
                .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("X-Forwarded-Host"))
                .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON)
                        .header("Set-Cookie", "LOOKAHEAD_SESSION=rotated; HttpOnly; SameSite=Lax")
                        .header("Set-Cookie", "LOOKAHEAD_GATEWAY=unexpected"));
        var response = proxy.identity(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().get("Set-Cookie")).containsExactly("LOOKAHEAD_SESSION=rotated; HttpOnly; SameSite=Lax");
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        upstream.verify();
    }

    @Test void standardTokenClientAuthenticationStaysOnIdentityEndpoint() throws Exception {
        var request = new MockHttpServletRequest("POST", "/oauth2/token");
        request.addHeader("Authorization", "Basic synthetic");
        upstream.expect(requestTo("http://identity:8080/oauth2/token"))
                .andExpect(header("Authorization", "Basic synthetic"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED).header("WWW-Authenticate", "Basic realm=identity"));
        var response = proxy.identity(request);
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getHeaders().getFirst("WWW-Authenticate")).isEqualTo("Basic realm=identity");
        upstream.verify();
    }

    @Test void retainsAuthorizationRedirectForBrowserWithoutFollowingIt() throws Exception {
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        request.setQueryString("client_id=lookahead-candidate");
        upstream.expect(requestTo("http://identity:8080/oauth2/authorize?client_id=lookahead-candidate"))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", settings.frontend() + "/sign-in?oauth=continue"));
        var response = proxy.identity(request);
        assertThat(response.getStatusCode().value()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst("Location")).startsWith(settings.frontend());
        upstream.verify();
    }

    @Test void rejectsForeignOriginBeforeContactingIdentity() throws Exception {
        var request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        request.addHeader("Origin", "https://attacker.test");
        assertThat(proxy.identity(request).getStatusCode().value()).isEqualTo(403);
        upstream.verify();
    }

    @Test void preservesAlreadyEncodedOAuthQueryValuesExactly() throws Exception {
        var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        String query = "redirect_uri=http%3A%2F%2F127.0.0.1%3A4350%2Flogin%2Foauth2%2Fcode%2Flookahead&state=a%2Bb";
        request.setQueryString(query);
        upstream.expect(requestTo("http://identity:8080/oauth2/authorize?" + query))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", settings.frontend() + "/callback"));
        assertThat(proxy.identity(request).getStatusCode().value()).isEqualTo(302);
        upstream.verify();
    }

    @Test void capsRequestAndResponseBodies() throws Exception {
        var large = new MockHttpServletRequest("POST", "/api/v1/auth/register");
        large.setContent(new byte[IdentityProxyController.MAX_BYTES + 1]);
        assertThat(proxy.identity(large).getStatusCode().value()).isEqualTo(413);
        upstream.expect(requestTo("http://identity:8080/oauth2/jwks"))
                .andRespond(withSuccess(new byte[IdentityProxyController.MAX_BYTES + 1], MediaType.APPLICATION_JSON));
        assertThat(proxy.identity(new MockHttpServletRequest("GET", "/oauth2/jwks")).getStatusCode().value()).isEqualTo(502);
        upstream.verify();
    }

    @Test void internalVerifierAndProductRoutesAreAbsentFromIdentityAllowlist() {
        assertThat(IdentityProxyController.PATHS).doesNotContain("/internal/v1/tokens/verify", "/api/v1/auth/me", "/api/v1/plans");
    }
}
