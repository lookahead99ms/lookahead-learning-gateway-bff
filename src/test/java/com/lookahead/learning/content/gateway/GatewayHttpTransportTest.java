package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import static org.assertj.core.api.Assertions.assertThat;

/** Exercises the actual production request factory, not RestClient's default test transport. */
class GatewayHttpTransportTest {
    private HttpServer upstream;
    private String origin;
    private final AtomicInteger redirected = new AtomicInteger();
    private static final String INVALID_CURRENT = "{\"status\":401,\"code\":\"INVALID_CURRENT_PASSWORD\",\"message\":\"Current password could not be verified\"}";

    @BeforeEach void start() throws Exception {
        upstream = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        upstream.createContext("/api/v1/account/password", exchange -> {
            exchange.getRequestBody().readAllBytes();
            byte[] body = INVALID_CURRENT.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(401, body.length);
            try (var output = exchange.getResponseBody()) { output.write(body); }
        });
        upstream.createContext("/oauth2/authorize", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Location", "/must-not-follow");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        upstream.createContext("/must-not-follow", exchange -> {
            redirected.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        upstream.start();
        origin = "http://127.0.0.1:" + upstream.getAddress().getPort();
    }

    @AfterEach void stop() { upstream.stop(0); }

    @Test void productionTransportPreservesPost401JsonAndCurrentBffSession() throws Exception {
        var account = new AccountProxyController(proxy(), new MockEnvironment());
        var request = new MockHttpServletRequest("POST", "/api/v1/account/password");
        request.addHeader("Content-Type", "application/json");
        request.setContent("{\"currentPassword\":\"synthetic wrong password\"}".getBytes(StandardCharsets.UTF_8));
        var session = new MockHttpSession();
        request.setSession(session);
        var response = account.password(request);
        assertThat(response.getStatusCode().value()).isEqualTo(401);
        assertThat(response.getBody()).isEqualTo(INVALID_CURRENT.getBytes(StandardCharsets.UTF_8));
        assertThat(response.getHeaders().getContentType().toString()).isEqualTo("application/json");
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
        assertThat(session.isInvalid()).isFalse();
    }

    @Test void productionTransportDoesNotFollowIdentityRedirect() throws Exception {
        var response = proxy().identity(new MockHttpServletRequest("GET", "/oauth2/authorize"));
        assertThat(response.getStatusCode().value()).isEqualTo(302);
        assertThat(response.getHeaders().getFirst(HttpHeaders.LOCATION)).isEqualTo("/must-not-follow");
        assertThat(redirected).hasValue(0);
    }

    private IdentityProxyController proxy() {
        var properties = new OAuthProperties(origin, origin, "synthetic-long-client-secret-testing", "test-client", origin,
                "http://domain-api:8080", Duration.ofSeconds(3), Duration.ofSeconds(7));
        var settings = new OAuthSettings(origin, "test-client", "synthetic-long-client-secret-testing", origin,
                "http://domain-api:8080", origin);
        return new IdentityProxyController(settings, new GatewayClientConfiguration().gatewayHttp(properties), "IDENTITY_TEST");
    }
}
