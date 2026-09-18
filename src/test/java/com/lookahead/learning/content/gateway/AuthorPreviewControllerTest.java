package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
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
        var controller = new AuthorPreviewController(request -> {
            calls.incrementAndGet();
            return authorizedClient();
        }, null);
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
                    .isEqualTo(AuthorPreviewSettingsTest.SOURCE_SECRET);
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
        var controller = new AuthorPreviewController(manager, proxy(builder));
        var result = controller.preview(request, servletResponse, principal);
        assertThat(result.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(result.getBody(), java.nio.charset.StandardCharsets.UTF_8))
                .isEqualTo("<html>synthetic private preview</html>");
        server.verify();
    }

    @Test void normalizesMissingOrFailedSessionClientAuthorizationWithoutSourceAccess() {
        for (OAuth2AuthorizedClientManager manager : new OAuth2AuthorizedClientManager[]{
                request -> null,
                request -> { throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant")); }}) {
            var response = new AuthorPreviewController(manager, null)
                    .preview(request(), new MockHttpServletResponse(), principal());
            assertThat(response.getStatusCode().value()).isEqualTo(401);
            assertThat(response.getBody()).isEmpty();
        }
        var controller = new AuthorPreviewController(request -> {
            throw new ResourceAccessException("synthetic token service unavailable");
        }, null);
        var response = controller.preview(request(), new MockHttpServletResponse(), principal());
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(response.getBody()).isEmpty();
    }

    @Test void mvcMappingAllowsOnlyReadMethodsAndPreservesDeniedResponses() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(ACCESS)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo(ACCESS)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        var controller = new AuthorPreviewController(request -> authorizedClient(), proxy(builder));
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

    private static AuthorPreviewProxy proxy(RestClient.Builder builder) {
        return new AuthorPreviewProxy(new AuthorPreviewSettings(URI.create("http://127.0.0.1:4315"),
                AuthorPreviewSettingsTest.SOURCE_SECRET), AuthorPreviewSettingsTest.OAUTH, builder.build());
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
}
