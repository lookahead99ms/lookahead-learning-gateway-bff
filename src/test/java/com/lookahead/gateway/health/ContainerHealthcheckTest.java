package com.lookahead.gateway.health;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
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

    @Test void probeFollowsTheRuntimeModeOfTheTaskDefinition() {
        // Infra's lower-cost DEV task sets LOOKAHEAD_RUNTIME_MODE=lower-cost-dev; actuator then lives only on loopback 8081.
        assertEquals(URI.create("http://127.0.0.1:8081/actuator/health/readiness"), ContainerHealthcheck.readinessUri("lower-cost-dev"));
        for (String other : new String[]{null, "", "local", "LOWER-COST-DEV", "lower-cost-dev "})
            assertEquals(ContainerHealthcheck.READINESS_URI, ContainerHealthcheck.readinessUri(other), String.valueOf(other));
        assertEquals("127.0.0.1", ContainerHealthcheck.MANAGEMENT_READINESS_URI.getHost());
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

    // ----- DLV-969 (owner, 2026-11-04): a failed probe says why in the application's own log stream -----

    @TempDir Path directory;
    final ByteArrayOutputStream written = new ByteArrayOutputStream();
    final ContainerHealthcheck.Sink sink = () -> new OutputStream() {
        @Override public void write(int b) { written.write(b); }
        @Override public void write(byte[] bytes, int offset, int length) { written.write(bytes, offset, length); }
    };

    void answer(int status, String body) {
        server.createContext("/actuator/health/readiness", exchange -> {
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0) exchange.getResponseBody().write(bytes);
            exchange.close();
        });
    }

    List<tools.jackson.databind.JsonNode> lines() {
        var mapper = new tools.jackson.databind.ObjectMapper();
        return written.toString(StandardCharsets.UTF_8).lines().map(mapper::readTree).toList();
    }

    @Test void eachFailureHasAReasonCodeAndWordsButNeverTheAnswerBody() throws Exception {
        answer(503, "{\"status\":\"OUT_OF_SERVICE\",\"secret\":\"synthetic-body-secret\"}");
        var notReady = ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri);
        assertEquals(1, notReady.code());
        assertEquals("NOT_READY", notReady.reason());
        assertTrue(notReady.words().startsWith("readiness answered 503 OUT_OF_SERVICE: "), notReady.words());
        assertFalse(notReady.words().contains("synthetic-body-secret"));
        server.removeContext("/actuator/health/readiness");
        answer(500, "synthetic-body-secret");
        assertEquals("HTTP_500", ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri).reason());
        server.removeContext("/actuator/health/readiness");
        answer(200, "{\"status\":\"UP\",\"components\":{}}");
        assertEquals("UNEXPECTED_ANSWER", ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri).reason());
        server.removeContext("/actuator/health/readiness");
        answer(503, "");
        assertEquals("readiness answered 503: the Gateway is starting, shutting down or refusing traffic (see its Readiness and Health check lines)",
                ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri).words());
        server.removeContext("/actuator/health/readiness");
        answer(200, "{\"status\":\"UP\"}");
        assertEquals(ContainerHealthcheck.Result.PASSED, ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri));
        server.stop(0);
        server = null;
        var refused = ContainerHealthcheck.probe(HttpClient.newHttpClient(), uri);
        assertEquals("CONNECTION_REFUSED", refused.reason());
        assertTrue(refused.words().startsWith("nothing is listening on 127.0.0.1:"), refused.words());
        assertEquals("NO_ANSWER", ContainerHealthcheck.probe(HttpClient.newHttpClient(), URI.create("file:///not-a-probe")).reason());
    }

    @Test void timeoutAndInterruptionHaveTheirOwnReasons() throws Exception {
        HttpClient client = mock(HttpClient.class);
        when(client.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new HttpTimeoutException("synthetic timeout"));
        assertEquals("TIMEOUT", ContainerHealthcheck.probe(client, uri).reason());
        HttpClient interrupted = mock(HttpClient.class);
        when(interrupted.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenThrow(new InterruptedException("synthetic"));
        try {
            assertEquals("INTERRUPTED", ContainerHealthcheck.probe(interrupted, uri).reason());
        } finally {
            Thread.interrupted();
        }
        HttpClient broken = mock(HttpClient.class);
        when(broken.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("synthetic-message-secret", new IllegalStateException("synthetic-cause-secret")));
        var noAnswer = ContainerHealthcheck.probe(broken, uri);
        assertEquals("NO_ANSWER", noAnswer.reason());
        assertTrue(noAnswer.words().endsWith("(IOException < IllegalStateException)"), noAnswer.words());
        assertFalse(noAnswer.words().contains("secret"));
    }

    @Test void failuresAreWrittenOnChangeThenOnceAMinuteAndRecoveryOnce() throws Exception {
        Path state = directory.resolve("state");
        Instant start = Instant.parse("2026-11-04T20:00:00Z");
        var refused = ContainerHealthcheck.Result.failed("CONNECTION_REFUSED", "nothing is listening on 127.0.0.1:8081");
        ContainerHealthcheck.report(ContainerHealthcheck.Result.PASSED, uri, state, sink, start, "dev");
        assertEquals(0, written.size());  // healthy and nothing before: silent
        ContainerHealthcheck.report(refused, uri, state, sink, start, "dev");
        ContainerHealthcheck.report(refused, uri, state, sink, start.plusSeconds(15), "dev");
        ContainerHealthcheck.report(refused, uri, state, sink, start.plusSeconds(30), "dev");
        assertEquals(1, lines().size());
        var first = lines().getFirst();
        assertEquals("WARN", first.at("/log/level").asString());
        assertEquals("lookahead.lifecycle", first.at("/log/logger").asString());
        assertEquals("gateway", first.at("/service/name").asString());
        assertEquals("health.container-check", first.at("/event/action").asString());
        assertEquals("CONNECTION_REFUSED", first.get("reason").asString());
        assertEquals("Container health check failed (CONNECTION_REFUSED): nothing is listening on 127.0.0.1:8081; probe 127.0.0.1:"
                + uri.getPort() + "/actuator/health/readiness, 1 failed in a row", first.get("message").asString());
        assertEquals("CONNECTION_REFUSED " + start.getEpochSecond() + " " + start.getEpochSecond() + " 3", Files.readString(state));
        // A different reason is written at once; the same one again only after a minute.
        var notReady = ContainerHealthcheck.Result.failed("NOT_READY", "readiness answered 503");
        ContainerHealthcheck.report(notReady, uri, state, sink, start.plusSeconds(45), "dev");
        ContainerHealthcheck.report(notReady, uri, state, sink, start.plusSeconds(60), "dev");
        ContainerHealthcheck.report(notReady, uri, state, sink, start.plusSeconds(105), "dev");
        assertEquals(3, lines().size());
        assertEquals(6, lines().get(2).get("failures").asInt());
        assertEquals(105, lines().get(2).get("downSeconds").asInt());
        ContainerHealthcheck.report(ContainerHealthcheck.Result.PASSED, uri, state, sink, start.plusSeconds(120), "dev");
        ContainerHealthcheck.report(ContainerHealthcheck.Result.PASSED, uri, state, sink, start.plusSeconds(135), "dev");
        assertEquals(4, lines().size());
        var recovered = lines().getLast();
        assertEquals("INFO", recovered.at("/log/level").asString());
        assertEquals("Container health check passed again after 120 s and 6 failed probes (last reason NOT_READY)", recovered.get("message").asString());
        assertFalse(Files.exists(state));
        assertFalse(written.toString(StandardCharsets.UTF_8).contains("ERROR"));
    }

    @Test void writingTheLineNeverChangesTheOutcome() throws Exception {
        var refused = ContainerHealthcheck.Result.failed("CONNECTION_REFUSED", "nothing is listening");
        var originalErr = System.err;
        var err = new ByteArrayOutputStream();
        System.setErr(new java.io.PrintStream(err, true, StandardCharsets.UTF_8));
        try {
            // The application's stdout cannot be opened: the line goes to this probe's stderr instead.
            ContainerHealthcheck.report(refused, uri, directory.resolve("state"), () -> { throw new IOException("synthetic"); }, Instant.now(), null);
        } finally {
            System.setErr(originalErr);
        }
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("\"reason\":\"CONNECTION_REFUSED\""));
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("\"environment\":\"dev\""));
        // An unwritable state file or a damaged one is ignored.
        ContainerHealthcheck.report(refused, uri, directory.resolve("missing").resolve("state"), sink, Instant.now(), "dev");
        Files.writeString(directory.resolve("damaged"), "CONNECTION_REFUSED x y z");
        ContainerHealthcheck.report(refused, uri, directory.resolve("damaged"), sink, Instant.now(), "dev");
        Files.writeString(directory.resolve("short"), "garbage");
        ContainerHealthcheck.report(refused, uri, directory.resolve("short"), sink, Instant.now(), "dev");
        assertEquals("CONNECTION_REFUSED", lines().getLast().get("reason").asString());
    }

    @Test void theLineIsValidJsonWhateverTheWords() {
        String line = ContainerHealthcheck.line(Instant.EPOCH, "dev", "WARN", "failure", "X", "quote \" backslash \\ newline \n tab \t", 1, 2);
        var json = new tools.jackson.databind.ObjectMapper().readTree(line);
        assertEquals("quote \" backslash \\ newline \n tab \t", json.get("message").asString());
        assertEquals(1, json.get("failures").asInt());
        assertEquals("1970-01-01T00:00:00Z", json.get("@timestamp").asString());
    }
}
