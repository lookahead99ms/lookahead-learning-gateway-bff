package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthPropertiesConfiguration;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import static org.assertj.core.api.Assertions.assertThat;

/** Real Tomcat requests catch parameter parsing that consumes POST form streams before MVC. */
@SpringBootTest(classes = IdentityProxyServletIntegrationTest.Application.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=identity-proxy-servlet-test", "app.deployment-environment=local",
                "app.oauth.issuer=http://localhost:19001", "app.oauth.frontend=http://localhost:19001",
                "app.oauth.client-secret=synthetic-client-secret-for-servlet-test",
                "app.oauth.client-id=lookahead-servlet-test", "app.oauth.domain-api-upstream=http://domain-api:8080",
                "app.gateway.identity-cookie-name=LOOKAHEAD_TEST_IDENTITY"})
@ActiveProfiles("gateway")
class IdentityProxyServletIntegrationTest {
    private static final String FRONTEND = "http://localhost:19001";
    private static final String LOGIN_FORM = "username=learner%2Btag%40example.test&password=synthetic%2Bpass%26word%3D%25";
    private static final String CLIENT_AUTH = "Basic c3ludGhldGljOmNsaWVudC1zZWNyZXQ=";
    private static final ConcurrentLinkedQueue<UpstreamRequest> RECEIVED = new ConcurrentLinkedQueue<>();
    private static final HttpServer IDENTITY = identityServer();
    private final HttpClient browser = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
    @LocalServerPort int port;

    @Configuration
    @EnableAutoConfiguration
    @Import({GatewayConfiguration.class, GatewayClientConfiguration.class, OAuthPropertiesConfiguration.class,
            IdentityProxyController.class, GatewayErrorHandler.class})
    static class Application { }

    @DynamicPropertySource static void upstream(DynamicPropertyRegistry properties) {
        properties.add("app.oauth.identity-upstream", () -> "http://127.0.0.1:" + IDENTITY.getAddress().getPort());
    }
    @BeforeEach void clearRequests() { RECEIVED.clear(); }
    @AfterAll static void stopIdentity() { IDENTITY.stop(0); }

    @Test void formLoginPreservesBytesAndOnlyIdentityCookieAndCsrf() throws Exception {
        var response = post("/api/v1/auth/login", LOGIN_FORM, Map.of(
                "Origin", FRONTEND, "X-CSRF-TOKEN", "identity-csrf",
                "Cookie", "LOOKAHEAD_GATEWAY=gateway-session; LOOKAHEAD_TEST_IDENTITY=identity-session",
                "Authorization", "Bearer browser-controlled"));
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("cache-control")).contains("no-store");
        assertThat(response.headers().firstValue("x-frame-options")).contains("DENY");
        assertThat(response.headers().firstValue("content-security-policy")).contains("frame-ancestors 'none'");
        var forwarded = RECEIVED.remove();
        assertThat(forwarded.body()).isEqualTo(LOGIN_FORM);
        assertThat(forwarded.cookie()).isEqualTo("LOOKAHEAD_TEST_IDENTITY=identity-session");
        assertThat(forwarded.csrf()).isEqualTo("identity-csrf");
        assertThat(forwarded.authorization()).isNull();
        assertThat(response.headers().firstValue("set-cookie")).isEmpty();
    }

    @Test void authorizationServerFormEndpointsRetainEveryEncodedParameterAndClientCredential() throws Exception {
        var forms = Map.of(
                "/oauth2/token", "grant_type=authorization_code&code=code%2Bvalue%2F%3D&code_verifier=synthetic_verifier",
                "/oauth2/revoke", "token=synthetic%2Btoken%2F%3D&token_type_hint=refresh_token",
                "/oauth2/introspect", "token=synthetic%2Btoken%2F%3D&token_type_hint=access_token");
        for (var entry : forms.entrySet()) {
            var response = post(entry.getKey(), entry.getValue(), Map.of("Authorization", CLIENT_AUTH));
            assertThat(response.statusCode()).isEqualTo(200);
            var forwarded = RECEIVED.remove();
            assertThat(forwarded.path()).isEqualTo(entry.getKey());
            assertThat(forwarded.body()).isEqualTo(entry.getValue());
            assertThat(forwarded.authorization()).isEqualTo(CLIENT_AUTH);
            assertThat(forwarded.csrf()).isNull();
        }
    }

    @Test void identityStillRejectsMissingCsrfAndGatewayRejectsForeignOrigin() throws Exception {
        var rejectedByIdentity = post("/api/v1/auth/login", LOGIN_FORM,
                Map.of("Cookie", "LOOKAHEAD_TEST_IDENTITY=identity-session"));
        assertThat(rejectedByIdentity.statusCode()).isEqualTo(403);
        assertThat(RECEIVED.remove().body()).isEqualTo(LOGIN_FORM);
        var foreignOrigin = post("/api/v1/auth/login", LOGIN_FORM,
                Map.of("Origin", "https://untrusted.example", "X-CSRF-TOKEN", "identity-csrf"));
        assertThat(foreignOrigin.statusCode()).isEqualTo(403);
        assertThat(RECEIVED).isEmpty();
    }

    @Test void bffOAuthAndPrivateRouteProtectionsRemainInTheirOwnChain() throws Exception {
        var authorization = get("/oauth2/authorization/lookahead");
        assertThat(authorization.statusCode()).isEqualTo(302);
        assertThat(authorization.headers().firstValue("location").orElseThrow())
                .startsWith(FRONTEND + "/oauth2/authorize?")
                .contains("code_challenge=", "code_challenge_method=S256", "state=", "nonce=");
        assertThat(get("/bff/api/v1/plans").statusCode()).isEqualTo(401);
        assertThat(post("/bff/api/v1/plans", "x=y", Map.of()).statusCode()).isEqualTo(403);
        assertThat(post("/internal/v1/tokens/verify", "token=synthetic", Map.of()).statusCode()).isEqualTo(403);
        assertThat(RECEIVED).isEmpty();
    }

    private HttpResponse<String> post(String path, String body, Map<String, String> headers) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .header("Content-Type", "application/x-www-form-urlencoded");
        headers.forEach(request::header);
        return browser.send(request.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build(),
                HttpResponse.BodyHandlers.ofString());
    }
    private HttpResponse<String> get(String path) throws Exception {
        return browser.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }
    private static HttpServer identityServer() {
        try {
            var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String cookie = exchange.getRequestHeaders().getFirst("Cookie");
                String csrf = exchange.getRequestHeaders().getFirst("X-CSRF-TOKEN");
                String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                RECEIVED.add(new UpstreamRequest(path, body, cookie, csrf, authorization));
                int status = 200;
                if (path.equals("/api/v1/auth/login")) {
                    if (!"identity-csrf".equals(csrf) || !"LOOKAHEAD_TEST_IDENTITY=identity-session".equals(cookie)) status = 403;
                    else if (!LOGIN_FORM.equals(body)) status = 401;
                } else if (body.isEmpty() || !CLIENT_AUTH.equals(authorization)) status = 400;
                byte[] response = "{}".getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, response.length);
                try (var output = exchange.getResponseBody()) { output.write(response); }
            });
            server.start();
            return server;
        } catch (IOException failure) { throw new IllegalStateException("Could not start test Identity endpoint", failure); }
    }
    private record UpstreamRequest(String path, String body, String cookie, String csrf, String authorization) { }
}
