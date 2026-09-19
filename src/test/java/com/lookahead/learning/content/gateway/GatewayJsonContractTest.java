package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.CsrfView;
import com.lookahead.learning.content.oauth.OAuthPropertiesConfiguration;
import com.lookahead.learning.content.oauth.OAuthSettings;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/** Wire contracts remain stable when transport types are owned by this application. */
@SpringBootTest(classes = GatewayJsonContractTest.Application.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=json-contract-test", "app.deployment-environment=local",
                "app.oauth.issuer=http://127.0.0.1:4331", "app.oauth.frontend=http://127.0.0.1:4331",
                "app.oauth.client-secret=synthetic-client-secret-for-json-contract",
                "app.oauth.client-id=lookahead-json-contract",
                "app.oauth.identity-upstream=http://identity:8080",
                "app.oauth.domain-api-upstream=http://domain-api:8080"})
@ActiveProfiles("gateway")
class GatewayJsonContractTest {
    private static final Instant TIMESTAMP = Instant.parse("2026-09-18T00:00:00Z");
    private static final String ACCESS_TOKEN = "synthetic-server-held-access-token";
    private final OAuthSettings settings = new OAuthSettings("http://127.0.0.1:4331", "lookahead-json-contract",
            "synthetic-client-secret-for-json-contract", "http://identity:8080", "http://domain-api:8080",
            "http://127.0.0.1:4331");

    @LocalServerPort int port;
    @Autowired ObjectMapper mapper;

    @Configuration
    @EnableAutoConfiguration
    @Import({GatewayConfiguration.class, GatewayClientConfiguration.class, OAuthPropertiesConfiguration.class,
            GatewayController.class, GatewayErrorHandler.class})
    static class Application { }

    @Test void browserCsrfResponsePreservesNamesTimestampAndCredentialBoundary() throws Exception {
        var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:" + port + "/bff/api/v1/auth/csrf")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("cache-control")).contains("no-store");
        var json = mapper.readTree(response.body());
        assertThat(json.propertyNames()).containsExactlyInAnyOrder("data", "timestamp");
        assertThat(json.path("data").propertyNames()).containsExactlyInAnyOrder("token", "headerName", "parameterName");
        assertThat(json.path("data").path("token").asString()).isNotBlank();
        assertThat(json.path("data").path("headerName").asString()).isEqualTo("X-CSRF-TOKEN");
        assertThat(json.path("data").path("parameterName").asString()).isEqualTo("_csrf");
        assertThat(Instant.parse(json.path("timestamp").asString())).isBeforeOrEqualTo(Instant.now());
        assertThat(response.body()).doesNotContain("access_token", "refresh_token", "client_secret", settings.clientSecret());
    }

    @Test void historicalEnvelopeDeserializesWithMissingAndExplicitNullFields() {
        var type = mapper.getTypeFactory().constructParametricType(ApiResponse.class, CsrfView.class);
        ApiResponse<CsrfView> legacy = mapper.readValue("""
                {"data":{"token":"synthetic-csrf","headerName":"X-CSRF-TOKEN","parameterName":"_csrf"},
                 "timestamp":"2026-09-18T00:00:00Z"}
                """, type);
        assertThat(legacy).isEqualTo(new ApiResponse<>(new CsrfView("synthetic-csrf", "X-CSRF-TOKEN", "_csrf"), TIMESTAMP));
        for (String json : List.of("{}", "{\"data\":null,\"timestamp\":null}")) {
            ApiResponse<CsrfView> empty = mapper.readValue(json, type);
            assertThat(empty.data()).isNull();
            assertThat(empty.timestamp()).isNull();
        }
        assertThat(mapper.readValue("{\"token\":null}", CsrfView.class)).isEqualTo(new CsrfView(null, null, null));
    }

    @Test void nullDataAndLogoutEnvelopeKeepTheirPublishedShape() {
        assertThat(mapper.readTree(mapper.writeValueAsString(new ApiResponse<>(null, TIMESTAMP))))
                .isEqualTo(mapper.readTree("{\"data\":null,\"timestamp\":\"2026-09-18T00:00:00Z\"}"));
        var logout = mapper.readTree(mapper.writeValueAsString(new ApiResponse<>(
                Map.of("logoutUrl", "http://127.0.0.1:4331/connect/logout?post_logout_redirect_uri=synthetic"), TIMESTAMP)));
        assertThat(logout.propertyNames()).containsExactlyInAnyOrder("data", "timestamp");
        assertThat(logout.path("data").propertyNames()).containsExactly("logoutUrl");
    }

    @Test void domainAccountProjectionPassesOldNewAndNullFieldsWithoutRewritingOrCredentialHeaders() throws Exception {
        var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "synthetic-user"), "sub");
        var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");
        var registration = new GatewayClientConfiguration().gatewayClient(settings).findByRegistrationId("lookahead");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, authentication.getName(),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, ACCESS_TOKEN, TIMESTAMP, TIMESTAMP.plusSeconds(3600))));
        for (String payload : List.of(
                "{\"data\":{\"accountId\":\"aaaabbbb-cccc-dddd-eeee-ffffffffffff\",\"username\":\"learner@example.test\",\"displayName\":null,\"topicGrants\":[\"learn:core-java\"]},\"timestamp\":\"2026-09-18T00:00:00Z\"}",
                "{\"data\":{\"accountId\":\"aaaabbbb-cccc-dddd-eeee-ffffffffffff\",\"username\":\"learner@example.test\",\"displayName\":\"Learner\",\"topicGrants\":[],\"contentGrants\":[],\"authorPreview\":false,\"futureOptionalField\":null},\"timestamp\":\"2026-09-18T00:00:00Z\"}",
                "{\"data\":null,\"timestamp\":\"2026-09-18T00:00:00Z\"}")) {
            var builder = RestClient.builder();
            var upstream = MockRestServiceServer.bindTo(builder).build();
            var controller = new GatewayController(settings, manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
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
            assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).doesNotContain(ACCESS_TOKEN, settings.clientSecret());
            upstream.verify();
        }
    }

    @Test void identityPublicJsonPreservesAbsenceNullsAndStableErrorCodes() throws Exception {
        for (var sample : List.of(
                new IdentitySample("/api/v1/auth/options", HttpStatus.OK, "{\"data\":{\"registration\":true,\"google\":false,\"oauth\":true},\"timestamp\":null}"),
                new IdentitySample("/api/v1/auth/csrf", HttpStatus.OK, "{\"data\":{\"token\":\"synthetic\",\"headerName\":\"X-CSRF-TOKEN\",\"parameterName\":\"_csrf\"}}"),
                new IdentitySample("/api/v1/auth/login", HttpStatus.UNAUTHORIZED, "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in to continue\",\"details\":null}"))) {
            var builder = RestClient.builder();
            var upstream = MockRestServiceServer.bindTo(builder).build();
            upstream.expect(requestTo("http://identity:8080" + sample.path()))
                    .andExpect(headerDoesNotExist("Authorization"))
                    .andRespond(withStatus(sample.status()).contentType(MediaType.APPLICATION_JSON).body(sample.body())
                            .header("Authorization", "Basic synthetic-upstream-secret"));
            var controller = new IdentityProxyController(settings, builder.build(), "LOOKAHEAD_SESSION");
            var response = controller.identity(new MockHttpServletRequest("GET", sample.path()));
            assertThat(response.getStatusCode()).isEqualTo(sample.status());
            assertThat(response.getBody()).isEqualTo(sample.body().getBytes(StandardCharsets.UTF_8));
            assertThat(response.getHeaders().get("Authorization")).isNull();
            assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
            upstream.verify();
        }
    }

    @Test void gatewayErrorsKeepStableCodesAndNeverSerializeUpstreamExceptionSecrets() {
        var handler = new GatewayErrorHandler();
        var unavailable = handler.unavailable(new RestClientException("Bearer " + ACCESS_TOKEN + " " + settings.clientSecret()));
        var expired = handler.expired(new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", ACCESS_TOKEN, null)));
        assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
        assertThat(expired.getStatusCode().value()).isEqualTo(401);
        for (var response : List.of(unavailable, expired)) {
            var serialized = mapper.writeValueAsString(response.getBody());
            assertThat(mapper.readTree(serialized).propertyNames()).containsExactlyInAnyOrder("code", "message");
            assertThat(serialized).doesNotContain(ACCESS_TOKEN, settings.clientSecret(), "invalid_grant");
            assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        }
        assertThat(mapper.valueToTree(unavailable.getBody()).path("code").asString()).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(mapper.valueToTree(expired.getBody()).path("code").asString()).isEqualTo("SESSION_EXPIRED");
    }

    private record IdentitySample(String path, HttpStatus status, String body) { }
}
