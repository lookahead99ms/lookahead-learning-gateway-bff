package com.lookahead.gateway.health;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class ContainerHealthcheckTest {
    private HttpServer server;
    private URI uri;

    @BeforeEach void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/actuator/health/readiness");
        server.start();
    }

    @AfterEach void stopServer() {
        if (server != null) server.stop(0);
    }

    static Stream<Arguments> readinessResponses() {
        return Stream.of(
                Arguments.of(200, "{\"status\":\"UP\"}", 0),
                Arguments.of(200, " \n { \"status\" : \"UP\" } \n ", 0),
                Arguments.of(503, "{\"status\":\"UP\"}", 1),
                Arguments.of(200, "{\"status\":\"DOWN\"}", 1),
                Arguments.of(200, "{\"status\":\"UNKNOWN\"}", 1),
                Arguments.of(200, "{\"status\":\"UP\",\"components\":{}}", 1),
                Arguments.of(200, "prefix {\"status\":\"UP\"}", 1),
                Arguments.of(200, "not-json", 1),
                Arguments.of(200, "", 1));
    }

    @ParameterizedTest @MethodSource("readinessResponses")
    void acceptsOnlySuccessfulStrictReadiness(int status, String body, int expected) {
        AtomicInteger gets = new AtomicInteger();
        server.createContext("/actuator/health/readiness", exchange -> {
            if (exchange.getRequestMethod().equals("GET")) gets.incrementAndGet();
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        assertEquals(expected, ContainerHealthcheck.check(uri));
        assertEquals(1, gets.get());
    }

    @Test void doesNotFollowRedirectsToHealthyEndpoint() {
        AtomicInteger redirected = new AtomicInteger();
        server.createContext("/actuator/health/readiness", exchange -> {
            exchange.getResponseHeaders().add("Location", "/healthy");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.createContext("/healthy", exchange -> {
            redirected.incrementAndGet();
            byte[] body = "{\"status\":\"UP\"}".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        assertEquals(1, ContainerHealthcheck.check(uri));
        assertEquals(0, redirected.get());
    }

    @Test void connectionFailureIsUnhealthy() {
        server.stop(0);
        server = null;
        assertEquals(1, ContainerHealthcheck.check(uri));
    }

    @Test void invalidRequestUriIsUnhealthy() {
        assertEquals(1, ContainerHealthcheck.check(URI.create("file:///not-a-probe")));
    }

    @Test void timeoutIsUnhealthyAndRequestIsBounded() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new HttpTimeoutException("synthetic timeout"));
        assertEquals(1, ContainerHealthcheck.check(client, uri));
        ArgumentCaptor<HttpRequest> request = ArgumentCaptor.forClass(HttpRequest.class);
        verify(client).send(request.capture(), any(HttpResponse.BodyHandler.class));
        assertEquals(Duration.ofSeconds(3), request.getValue().timeout().orElseThrow());
        assertEquals("GET", request.getValue().method());
        assertEquals(uri, request.getValue().uri());
    }

    @Test void interruptedProbeFailsAndRestoresInterruptFlag() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new InterruptedException("synthetic interruption"));
        try {
            assertEquals(1, ContainerHealthcheck.check(client, uri));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
    }

    @Test void productionProbeRemainsFixedToContainerLoopback() {
        assertEquals(URI.create("http://127.0.0.1:8080/actuator/health/readiness"), ContainerHealthcheck.READINESS_URI);
    }
}
