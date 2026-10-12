package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class AccountProxyControllerTest {
    private final RestClient.Builder http = RestClient.builder();
    private final MockRestServiceServer upstream = MockRestServiceServer.bindTo(http).build();
    private final OAuthSettings settings = new OAuthSettings("http://127.0.0.1:4350", "lookahead-test",
            "synthetic-client-secret-only-for-testing", "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
    private final IdentityProxyController identity = new IdentityProxyController(settings, http.build(), "IDENTITY_TEST");
    private final MockEnvironment environment = new MockEnvironment()
            .withProperty("server.servlet.session.cookie.name", "GATEWAY_TEST")
            .withProperty("server.servlet.session.cookie.secure", "false");
    private final AccountProxyController account = new AccountProxyController(identity, environment);

    @AfterEach void clearContext() { SecurityContextHolder.clearContext(); upstream.verify(); }

    @Test void passwordSuccessClearsSessionAndOnlyExpiresConfiguredGatewayCookie() throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var session = new MockHttpSession();
        session.setAttribute("oauthClient", "synthetic-session-token");
        request.setSession(session);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "unused"));
        String body = "{\"currentPassword\":\"synthetic current\",\"newPassword\":\"synthetic new password\",\"confirmPassword\":\"synthetic new password\"}";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setCookies(new Cookie("GATEWAY_TEST", "gateway-secret"), new Cookie("IDENTITY_TEST", "identity-session"), new Cookie("OTHER", "unrelated"));
        request.addHeader("X-CSRF-TOKEN", "identity-csrf");
        request.addHeader("Authorization", "Bearer browser-token");
        request.addHeader("X-Forwarded-Host", "untrusted.test");
        upstream.expect(requestTo("http://identity:8080/api/v1/account/password"))
                .andExpect(method(HttpMethod.POST)).andExpect(content().string(body))
                .andExpect(header("Cookie", "IDENTITY_TEST=identity-session"))
                .andExpect(header("X-CSRF-TOKEN", "identity-csrf"))
                .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("X-Forwarded-Host"))
                .andRespond(withSuccess("{\"data\":{\"reauthenticationRequired\":true}}", MediaType.APPLICATION_JSON)
                        .header("Set-Cookie", "IDENTITY_TEST=; Path=/; Max-Age=0; HttpOnly")
                        .header("Set-Cookie", "OTHER=unexpected"));
        var response = account.password(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).hasSize(2);
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE).get(1))
                .startsWith("GATEWAY_TEST=;").contains("Path=/", "Max-Age=0", "HttpOnly", "SameSite=Lax").doesNotContain("Secure");
    }

    @ParameterizedTest @ValueSource(ints = {400, 401, 403, 409, 429, 500, 503})
    void rejectedPasswordChangePreservesBffSessionAndAuthentication(int status) throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var session = new MockHttpSession();
        request.setSession(session);
        var authentication = new UsernamePasswordAuthenticationToken("user", "unused");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        upstream.expect(requestTo("http://identity:8080/api/v1/account/password"))
                .andRespond(withStatus(HttpStatus.valueOf(status)).body(status >= 500 ? "database secret details" : "{\"code\":\"EXPECTED_ERROR\"}"));
        var response = account.password(request);
        assertThat(response.getStatusCode().value()).isEqualTo(status >= 500 ? 503 : status);
        assertThat(session.isInvalid()).isFalse();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
        assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).doesNotContain("database secret details");
    }

    @Test void profileSuccessDoesNotClearSessionOrRewrapAuthoritativeBody() throws Exception {
        var request = request("POST", "/api/v1/account/profile");
        var session = new MockHttpSession();
        request.setSession(session);
        String payload = "{\"data\":{\"accountId\":\"synthetic-id\",\"username\":\"learner@example.test\",\"displayName\":\"New name\"}}";
        upstream.expect(requestTo("http://identity:8080/api/v1/account/profile"))
                .andRespond(withSuccess(payload, MediaType.APPLICATION_JSON));
        assertThat(new String(account.profile(request).getBody(), StandardCharsets.UTF_8)).isEqualTo(payload);
        assertThat(session.isInvalid()).isFalse();
    }

    @ParameterizedTest @ValueSource(strings = {"/api/v1/account/preferences", "/api/v1/account/links"})
    void preferencesAndLinksRelayBodyCsrfAndAuthoritativeResponseWithoutClearingSession(String path) throws Exception {
        var request = request("POST", path);
        var session = new MockHttpSession();
        request.setSession(session);
        request.addHeader("X-CSRF-TOKEN", "identity-csrf");
        request.setCookies(new Cookie("IDENTITY_TEST", "identity-session"), new Cookie("GATEWAY_TEST", "gateway-session"));
        String body = path.endsWith("links")
                ? "{\"github\":\"https://github.com/learner\",\"linkedin\":null,\"x\":\"\",\"website\":null}"
                : "{\"theme\":\"dark\"}";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        String payload = "{\"data\":{\"accountId\":\"synthetic-id\",\"themePreference\":\"dark\",\"links\":{\"github\":null,\"linkedin\":null,\"x\":null,\"website\":null}}}";
        upstream.expect(requestTo("http://identity:8080" + path))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-CSRF-TOKEN", "identity-csrf"))
                .andExpect(header(HttpHeaders.COOKIE, "IDENTITY_TEST=identity-session"))
                .andExpect(content().string(body))
                .andRespond(withSuccess(payload, MediaType.APPLICATION_JSON));
        var response = account.preferences(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).isEqualTo(payload);
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
        assertThat(session.isInvalid()).isFalse();
    }

    @ParameterizedTest @ValueSource(ints = {401, 403, 422, 500, 503})
    void preferencesAndLinksKeepIdentityErrorsAndSanitizeInfrastructureFailures(int status) throws Exception {
        String[] paths = {"/api/v1/account/preferences", "/api/v1/account/links"};
        for (String path : paths)
            upstream.expect(requestTo("http://identity:8080" + path))
                    .andRespond(withStatus(HttpStatus.valueOf(status)).body(status >= 500 ? "database secret details" : "{\"code\":\"INVALID_PROFILE_LINK\"}"));
        for (String path : paths) {
            var request = request("POST", path);
            var session = new MockHttpSession();
            request.setSession(session);
            var response = account.preferences(request);
            assertThat(response.getStatusCode().value()).isEqualTo(status >= 500 ? 503 : status);
            assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).doesNotContain("database secret details");
            if (status < 500) assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).contains("INVALID_PROFILE_LINK");
            assertThat(session.isInvalid()).isFalse();
        }
    }

    @Test void oversizedOrForeignPreferenceAndLinkRequestsNeverReachIdentity() throws Exception {
        for (String path : new String[]{"/api/v1/account/preferences", "/api/v1/account/links"}) {
            var large = request("POST", path);
            large.setContent(new byte[AccountProxyController.MAX_ACCOUNT_BYTES + 1]);
            assertThat(account.preferences(large).getStatusCode().value()).isEqualTo(413);
            var foreign = request("POST", path);
            foreign.addHeader("Origin", "https://untrusted.example");
            assertThat(account.preferences(foreign).getStatusCode().value()).isEqualTo(403);
        }
    }

    @Test void oversizedPasswordBodyRejectedBeforeUpstreamAndSessionPreserved() throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var session = new MockHttpSession();
        request.setSession(session);
        request.setContent(new byte[AccountProxyController.MAX_ACCOUNT_BYTES + 1]);
        assertThat(account.password(request).getStatusCode().value()).isEqualTo(413);
        assertThat(session.isInvalid()).isFalse();
    }

    @Test void oversizedUpstreamResponseNeverClearsSession() throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var session = new MockHttpSession();
        request.setSession(session);
        upstream.expect(requestTo("http://identity:8080/api/v1/account/password"))
                .andRespond(withSuccess(new byte[AccountProxyController.MAX_ACCOUNT_BYTES + 1], MediaType.APPLICATION_JSON));
        assertThat(account.password(request).getStatusCode().value()).isEqualTo(503);
        assertThat(session.isInvalid()).isFalse();
    }

    @Test void successfulPasswordChangeWithoutGatewaySessionDoesNotCreateOneAndUsesSecureCookieInProduction() throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var secure = new AccountProxyController(identity, new MockEnvironment()
                .withProperty("server.servlet.session.cookie.name", "GATEWAY_PROD")
                .withProperty("server.servlet.session.cookie.path", "/")
                .withProperty("server.servlet.session.cookie.domain", "example.test"));
        upstream.expect(requestTo("http://identity:8080/api/v1/account/password"))
                .andRespond(withSuccess("{\"data\":{\"reauthenticationRequired\":true}}", MediaType.APPLICATION_JSON));
        assertThat(secure.password(request).getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .contains("GATEWAY_PROD=", "Secure", "Domain=example.test", "Path=/", "Max-Age=0");
        assertThat(request.getSession(false)).isNull();
    }

    @Test void foreignOriginRejectedWithoutInvalidatingSession() throws Exception {
        var request = request("POST", "/api/v1/account/password");
        var session = new MockHttpSession();
        request.setSession(session);
        request.addHeader("Origin", "https://untrusted.example");
        assertThat(account.password(request).getStatusCode().value()).isEqualTo(403);
        assertThat(session.isInvalid()).isFalse();
    }

    @Test void connectivityFailureUsesSanitizedAdviceAndPreservesSession() throws Exception {
        var session = new MockHttpSession();
        upstream.expect(requestTo("http://identity:8080/api/v1/account/password"))
                .andRespond(withException(new java.io.IOException("private-database-host credential-detail")));
        var mvc = org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(account)
                .setControllerAdvice(new GatewayErrorHandler()).build();
        var response = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/v1/account/password").session(session).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isServiceUnavailable())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.header().string("Cache-Control", "no-store"))
                .andReturn().getResponse();
        assertThat(response.getContentAsString()).contains("SERVICE_UNAVAILABLE")
                .doesNotContain("private-database-host", "credential-detail", "IOException", "stackTrace");
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).isNull();
        assertThat(session.isInvalid()).isFalse();
    }

    @ParameterizedTest @ValueSource(booleans = {true, false})
    void selectiveRevocationClearsOnlyWhenIdentityRequiresReauthentication(boolean reauthenticate) throws Exception {
        var request = request("POST", "/api/v1/account/sign-ins/revoke");
        var session = new MockHttpSession(); request.setSession(session);
        upstream.expect(requestTo("http://identity:8080/api/v1/account/sign-ins/revoke"))
                .andRespond(withSuccess("{\"data\":{\"reauthenticationRequired\":" + reauthenticate + "}}", MediaType.APPLICATION_JSON));
        var response = account.updateSignIns(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(session.isInvalid()).isEqualTo(reauthenticate);
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE) != null).isEqualTo(reauthenticate);
    }

    private MockHttpServletRequest request(String method, String path) {
        var request = new MockHttpServletRequest(method, path);
        request.addHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
        return request;
    }
}
