package com.lookahead.gateway.controller;

import com.lookahead.gateway.client.SignInTokenClient;
import ch.qos.logback.classic.Level;
import com.lookahead.gateway.client.AuthorPreviewDomainClient;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.proxy.AuthorPreviewProxy;
import com.lookahead.gateway.util.AuthorPreviewPath;
import com.lookahead.gateway.util.AuthorPreviewUpstream;
import com.lookahead.gateway.util.AuthorPreviewUpstreamTest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthorPreviewControllerTest {
    private static final String PATH = AuthorPreviewPath.PREFIX + "focus-studio/index.html";
    private static final String ACCESS = "http://domain-api:8080/api/v1/author/previews/access";
    private static final String SOURCE = "http://127.0.0.1:4315/focus-studio/index.html";

    @Test void rejectsNullWrongAndUnauthenticatedPrincipalsWithoutCallingTheManager() {
        var calls = new AtomicInteger();
        var controller = new AuthorPreviewController(proxy(request -> {
            calls.incrementAndGet();
            return authorizedClient();
        }, RestClient.builder()));
        var unauthenticated = principal();
        unauthenticated.setAuthenticated(false);
        for (Authentication auth : new Authentication[]{null,
                UsernamePasswordAuthenticationToken.authenticated("author@lookahead.test", "ignored", List.of()),
                unauthenticated}) {
            var response = controller.preview(request(), new MockHttpServletResponse(), auth);
            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).isEmpty();
        }
        assertThat(calls.get()).isZero();
    }

    @Test void obtainsOnlyTheSessionAuthorizedClientAndDoesNotForwardBrowserCredentials() {
        var request = request();
        request.setQueryString("theme=dark&label=a%20b");
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer browser-spoof-token");
        request.addHeader(HttpHeaders.COOKIE, "browser-session=private");
        request.addHeader(AuthorPreviewProxy.SOURCE_KEY_HEADER, "browser-spoof-source-key");
        request.addHeader("X-Author", "true");
        request.addHeader("X-Forwarded-Host", "other.test");
        var servletResponse = new MockHttpServletResponse();
        var principal = principal();
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ACCESS)).andExpect(sent -> {
            assertThat(sent.getHeaders().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer server-token");
            assertThat(sent.getHeaders().toSingleValueMap()).doesNotContainKeys(HttpHeaders.COOKIE, AuthorPreviewProxy.SOURCE_KEY_HEADER,
                    "X-Author", "X-Forwarded-Host");
        }).andRespond(withStatus(HttpStatus.NO_CONTENT));
        server.expect(requestTo(SOURCE + "?theme=dark&label=a%20b")).andExpect(sent -> {
            assertThat(sent.getHeaders().getFirst(AuthorPreviewProxy.SOURCE_KEY_HEADER))
                    .isEqualTo(AuthorPreviewUpstreamTest.SOURCE_SECRET);
            assertThat(sent.getHeaders().toSingleValueMap()).doesNotContainKeys(HttpHeaders.AUTHORIZATION, HttpHeaders.COOKIE,
                    "X-Author", "X-Forwarded-Host");
        }).andRespond(withSuccess("<html>synthetic private preview</html>", MediaType.TEXT_HTML));
        OAuth2AuthorizedClientManager manager = authorization -> {
            assertThat(authorization.getClientRegistrationId()).isEqualTo("lookahead");
            assertThat(authorization.getPrincipal()).isSameAs(principal);
            assertThat(authorization.getAttributes().get(HttpServletRequest.class.getName())).isSameAs(request);
            assertThat(authorization.getAttributes().get(HttpServletResponse.class.getName())).isSameAs(servletResponse);
            return authorizedClient();
        };
        var controller = new AuthorPreviewController(proxy(manager, builder));
        var result = controller.preview(request, servletResponse, principal);
        assertThat(result.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(result.getBody(), StandardCharsets.UTF_8))
                .isEqualTo("<html>synthetic private preview</html>");
        server.verify();
    }

    @Test void normalizesMissingOrFailedSessionClientAuthorizationWithoutSourceAccess() {
        for (OAuth2AuthorizedClientManager manager : new OAuth2AuthorizedClientManager[]{
                request -> null,
                request -> { throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant")); }}) {
            var response = new AuthorPreviewController(proxy(manager, RestClient.builder()))
                    .preview(request(), new MockHttpServletResponse(), principal());
            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).isEmpty();
        }
        var controller = new AuthorPreviewController(proxy(request -> {
            throw new ResourceAccessException("synthetic token service unavailable");
        }, RestClient.builder()));
        var response = controller.preview(request(), new MockHttpServletResponse(), principal());
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(response.getBody()).isEmpty();
    }

    @Test void mvcMappingAllowsOnlyReadMethodsAndPreservesDeniedResponses() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ACCESS)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo(ACCESS)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        var controller = new AuthorPreviewController(proxy(request -> authorizedClient(), builder));
        var mvc = MockMvcBuilders.standaloneSetup(controller).build();
        mvc.perform(get(PATH).principal(principal())).andExpect(status().isForbidden()).andExpect(content().bytes(new byte[0]));
        mvc.perform(head(PATH).principal(principal())).andExpect(status().isForbidden()).andExpect(content().bytes(new byte[0]));
        mvc.perform(post(PATH).principal(principal())).andExpect(status().isMethodNotAllowed());
        mvc.perform(get(PATH)).andExpect(status().isUnauthorized()).andExpect(content().bytes(new byte[0]));
        server.verify();
    }

    private static MockHttpServletRequest request() {
        return new MockHttpServletRequest("GET", PATH);
    }

    private static AuthorPreviewProxy proxy(OAuth2AuthorizedClientManager manager, RestClient.Builder builder) {
        var http = builder.build();
        return new AuthorPreviewProxy(new AuthorPreviewUpstream(URI.create("http://127.0.0.1:4315"),
                AuthorPreviewUpstreamTest.SOURCE_SECRET), new AuthorPreviewDomainClient(AuthorPreviewUpstreamTest.OAUTH, http), new SignInTokenClient(manager), http);
    }

    private static OAuth2AuthenticationToken principal() {
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
        return new OAuth2AuthenticationToken(new DefaultOAuth2User(authorities,
                Map.of("sub", "synthetic-author-subject", "name", "Author"), "sub"), authorities, "lookahead");
    }

    private static OAuth2AuthorizedClient authorizedClient() {
        var client = ClientRegistration.withRegistrationId("lookahead")
                .clientId("lookahead-web-gateway-dev").clientSecret("synthetic-client-secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://127.0.0.1:4301/login/oauth2/code/lookahead")
                .authorizationUri("http://127.0.0.1:4301/oauth2/authorize")
                .tokenUri("http://127.0.0.1:4301/oauth2/token").build();
        var now = Instant.now();
        return new OAuth2AuthorizedClient(client, "synthetic-author-subject",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-token", now, now.plusSeconds(300)));
    }

    /**
     * DLV-969 (owner, 2026-11-04): each fallback that used to answer 502 or 503 without a word now writes one WARN line with
     * what was being done and why: a stable reason code, the upstream status and exception types. Never a body or a token.
     */
    @Nested class FallbackReason {
    static final String SECRET = "synthetic-body-secret";
    static final String TOKEN = "synthetic-server-token";
    final LogCapture log = new LogCapture("lookahead.event");

    @AfterEach void close() { log.close(); }

    void reason(String action, String reason) {
        assertThat(log.lines()).isNotEmpty();
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.action=" + action, "reason=" + reason);
        log.assertNothing(SECRET, TOKEN);
    }

    @Test void authorPreviewFallbacksSayWhy() {
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        String access = "http://domain-api:8080/api/v1/author/previews/access", source = "http://127.0.0.1:4315/preview-directory/manifest.json";
        String path = AuthorPreviewPath.PREFIX + "preview-directory/manifest.json";
        var previewHttp = builder.build();
        var upstream = new AuthorPreviewUpstream(URI.create("http://127.0.0.1:4315"), AuthorPreviewUpstreamTest.SOURCE_SECRET);
        var domain = new AuthorPreviewDomainClient(AuthorPreviewUpstreamTest.OAUTH, previewHttp);
        var proxy = new AuthorPreviewProxy(upstream, domain, new SignInTokenClient(request -> null), previewHttp);
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.NO_CONTENT));
        server.expect(requestTo(source)).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.NO_CONTENT));
        server.expect(requestTo(source)).andRespond(withSuccess("x", MediaType.APPLICATION_JSON).header(HttpHeaders.CONTENT_LENGTH, String.valueOf(AuthorPreviewProxy.MAX_BYTES + 1)));
        server.expect(requestTo(access)).andRespond(withException(new IOException(SECRET)));
        assertThat(proxy.fetch("GET", path, null, TOKEN, null).getStatusCode().value()).isEqualTo(403);
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.outcome=refused", "reason=PREVIEW_ACCESS_REFUSED");
        assertThat(proxy.fetch("GET", path, null, TOKEN, null).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_ACCESS_CHECK_FAILED");
        assertThat(proxy.fetch("GET", path, null, TOKEN, null).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_SERVER_HTTP_503");
        assertThat(proxy.fetch("GET", path, null, TOKEN, null).getStatusCode().value()).isEqualTo(502);
        reason("author-preview.fetch", "PREVIEW_TOO_LARGE");
        assertThat(proxy.fetch("GET", path, null, TOKEN, null).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_UNAVAILABLE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Author preview answered 503: Domain or the local preview server did not answer "
                + "(ResourceAccessException < IOException) (PREVIEW_UNAVAILABLE)");
        server.verify();

        var principal = new OAuth2AuthenticationToken(new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "s"), "sub"),
                List.of(new SimpleGrantedAuthority("ROLE_USER")), "lookahead");
        OAuth2AuthorizedClientManager expired = request -> { throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", SECRET, null)); };
        var request = new MockHttpServletRequest("GET", path);
        assertThat(new AuthorPreviewController(new AuthorPreviewProxy(upstream, domain, new SignInTokenClient(expired), previewHttp)).preview(request, new MockHttpServletResponse(), principal).getStatusCode().value()).isEqualTo(401);
        assertThat(LogCapture.pairs(log.last())).contains("reason=SESSION_EXPIRED");
        assertThat(log.last().getFormattedMessage()).contains("(invalid_grant)");
        OAuth2AuthorizedClientManager down = request2 -> { throw new ResourceAccessException(SECRET); };
        assertThat(new AuthorPreviewController(new AuthorPreviewProxy(upstream, domain, new SignInTokenClient(down), previewHttp)).preview(request, new MockHttpServletResponse(), principal).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "TOKEN_REFRESH_UNAVAILABLE");
        // A request that never reaches an upstream (malformed path, missing token) stays quiet: the request line says it.
        log.clear();
        assertThat(proxy.fetch("GET", "/elsewhere", null, TOKEN, null).getStatusCode().value()).isEqualTo(400);
        assertThat(log.lines()).isEmpty();
    }
    }
}
