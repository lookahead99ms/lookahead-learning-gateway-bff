package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;

/**
 * DLV-1015: the connection step of the author-preview calls, driven directly: a redirect is never followed, for any
 * method, and the usual preparation (the timeouts, the method) still happens. The same through the configuration's
 * connection, the access check and the artifact fetch is in AuthorPreviewConfigurationTest.
 */
class AuthorPreviewRequestFactoryTest {
    @Test void everyConnectionIsPreparedNotToFollowRedirectsAndKeepsItsTimeoutsAndMethod() throws Exception {
        var factory = new AuthorPreviewRequestFactory();
        factory.setConnectTimeout(Duration.ofMillis(1200));
        factory.setReadTimeout(Duration.ofMillis(3400));
        for (String method : List.of("GET", "HEAD", "POST")) {
            // Nothing is sent: the connection is only prepared, never opened.
            var connection = (HttpURLConnection) URI.create("http://127.0.0.1:9/index.html").toURL().openConnection();
            connection.setInstanceFollowRedirects(true);
            factory.prepareConnection(connection, method);
            assertThat(connection.getInstanceFollowRedirects()).as(method).isFalse();
            assertThat(connection.getRequestMethod()).isEqualTo(method);
            assertThat(connection.getConnectTimeout()).isEqualTo(1200);
            assertThat(connection.getReadTimeout()).isEqualTo(3400);
        }
    }

    @Test void aRedirectAnswerComesBackAsItIsAndItsTargetIsNeverAsked() throws Exception {
        var targetRequests = new AtomicInteger();
        var http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/index.html", exchange -> {
            exchange.getResponseHeaders().set("Location", "/redirect-target");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        http.createContext("/redirect-target", exchange -> {
            targetRequests.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        http.start();
        try {
            var uri = URI.create("http://127.0.0.1:" + http.getAddress().getPort() + "/index.html");
            for (HttpMethod method : List.of(HttpMethod.GET, HttpMethod.HEAD)) {
                try (var answer = new AuthorPreviewRequestFactory().createRequest(uri, method).execute()) {
                    assertThat(answer.getStatusCode().value()).as(method.name()).isEqualTo(302);
                    assertThat(answer.getHeaders().getFirst("Location")).isEqualTo("/redirect-target");
                }
            }
            assertThat(targetRequests).hasValue(0);
        } finally {
            http.stop(0);
        }
    }
}
