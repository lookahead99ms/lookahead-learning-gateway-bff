package com.lookahead.gateway.health;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Container readiness probe using only the Java runtime already in the image.
 *
 * <p>DLV-969 (owner, 2026-11-04): ECS keeps a failed probe's output to itself, so a task stopped for "failed container
 * health checks" used to leave nothing in CloudWatch. A failed probe now writes one line to the application's own log
 * stream (the stdout of PID 1) saying why: nothing listening, no answer in time, or readiness answering 503 and its
 * status. Once when it starts failing or the reason changes, then at most once a minute while it keeps failing, and once
 * when it passes again; a small state file in {@code /tmp} remembers across probes. Writing the line never changes the
 * exit code.
 *
 * <p>Plain logs (owner decision 2026-11-17): the line has the application's own shape, "{@code <UTC timestamp with
 * millis> <LEVEL padded to 5> <sentence>}", with the reason code, the failures in a row and the seconds down in words.
 * A failing probe is WARN (the task is not serving yet, or is stopping); the word ERROR never appears, since the deploy's
 * log scan treats it as a failed start.
 *
 * <p>Exception, decided 2026-11-25 (DLV-1015): this class makes an HTTP call outside {@code client} (rule 4: only a
 * client class talks to an outside system). It is the stand-alone probe program the container runs in its own JVM
 * against the application's loopback address, compiled on its own for the image, so it cannot use the application's
 * classes.
 */
public final class ContainerHealthcheck {
    static final URI READINESS_URI = URI.create("http://127.0.0.1:8080/actuator/health/readiness");
    /** The lower-cost DEV profile serves actuator only on its loopback management port 8081 (application-lower-cost-dev.yml). */
    static final URI MANAGEMENT_READINESS_URI = URI.create("http://127.0.0.1:8081/actuator/health/readiness");
    static final Path STATE = Path.of("/tmp/lookahead-healthcheck.state");
    static final Path APPLICATION_LOG = Path.of("/proc/1/fd/1");
    static final Duration REPEAT = Duration.ofMinutes(1);
    /** The same timestamp shape as the application's console pattern: {@code 2026-11-17T20:41:18.144Z}. */
    static final DateTimeFormatter TIMESTAMP = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSX").withZone(ZoneOffset.UTC);
    private static final Pattern STATUS = Pattern.compile("\"status\"\\s*:\\s*\"([A-Z_]{1,32})\"");

    private ContainerHealthcheck() {
    }

    public static void main(String[] args) {
        URI uri = readinessUri(System.getenv("LOOKAHEAD_RUNTIME_MODE"));
        Result result = probe(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build(), uri);
        report(result, uri, STATE, ContainerHealthcheck::applicationLog, Instant.now());
        System.exit(result.code());
    }

    /** ECS sets LOOKAHEAD_RUNTIME_MODE=lower-cost-dev; every other mode keeps the container port 8080 probe. */
    static URI readinessUri(String runtimeMode) {
        return "lower-cost-dev".equals(runtimeMode) ? MANAGEMENT_READINESS_URI : READINESS_URI;
    }

    /** The probe's outcome: exit code 0 or 1, a reason code and the reason in words. */
    record Result(int code, String reason, String words) {
        static final Result PASSED = new Result(0, "READY", "readiness answered UP");
        static Result failed(String reason, String words) { return new Result(1, reason, words); }
    }

    static Result probe(HttpClient client, URI readinessUri) {
        String where = readinessUri.getHost() + ":" + readinessUri.getPort();
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(readinessUri)
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            String body = response.body() == null ? "" : response.body();
            if (status == 200 && body.matches("\\s*\\{\\s*\"status\"\\s*:\\s*\"UP\"\\s*}\\s*")) return Result.PASSED;
            Matcher reported = STATUS.matcher(body.length() > 512 ? body.substring(0, 512) : body);
            String health = reported.find() ? reported.group(1) : null;
            if (status == 503) return Result.failed("NOT_READY", "readiness answered 503" + (health == null ? "" : " " + health)
                    + ": the Gateway is starting, shutting down or refusing traffic (see its Readiness and Health check lines)");
            if (status == 200) return Result.failed("UNEXPECTED_ANSWER", "readiness answered 200 but not exactly {\"status\":\"UP\"}");
            return Result.failed("HTTP_" + status, "readiness answered HTTP " + status + " instead of 200");
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return Result.failed("INTERRUPTED", "the probe was interrupted");
        } catch (HttpTimeoutException exception) {
            return Result.failed("TIMEOUT", "no answer from " + where + " in time: the Gateway is overloaded, paused or hung");
        } catch (ConnectException exception) {
            return Result.failed("CONNECTION_REFUSED", "nothing is listening on " + where + ": the Gateway is still starting, or its "
                    + "web server stopped");
        } catch (Exception exception) {
            return Result.failed("NO_ANSWER", "the probe got no answer from " + where + " (" + types(exception) + ")");
        }
    }

    /** Where the line goes: the application's own stdout, which the awslogs driver ships; this process's stderr otherwise. */
    interface Sink { OutputStream open() throws IOException; }

    static OutputStream applicationLog() throws IOException {
        return new FileOutputStream(APPLICATION_LOG.toFile(), true);
    }

    /**
     * Writes the line if this probe changes what the last ones said, or a minute has passed while it keeps failing. The
     * state file holds {@code reason firstFailedEpochSecond lastLoggedEpochSecond failures}; it is gone while all is well.
     */
    static void report(Result result, URI uri, Path state, Sink sink, Instant now) {
        try {
            String[] previous = Files.exists(state) ? Files.readString(state, StandardCharsets.US_ASCII).strip().split(" ") : null;
            if (previous != null && previous.length != 4) previous = null;
            if (result.code() == 0) {
                if (previous == null) return;
                long downSeconds = now.getEpochSecond() - Long.parseLong(previous[1]);
                write(sink, line(now, "INFO", "Container health check passed again: READY after " + downSeconds + " s down and " + previous[3]
                        + " failed " + (previous[3].equals("1") ? "probe" : "probes") + " (last reason " + previous[0] + ")"));
                Files.deleteIfExists(state);
                return;
            }
            boolean continuing = previous != null;
            long first = continuing ? Long.parseLong(previous[1]) : now.getEpochSecond();
            long lastLogged = continuing ? Long.parseLong(previous[2]) : 0;
            long failures = continuing ? Long.parseLong(previous[3]) + 1 : 1;
            boolean due = !continuing || !previous[0].equals(result.reason()) || now.getEpochSecond() - lastLogged >= REPEAT.toSeconds();
            if (due) {
                long downSeconds = now.getEpochSecond() - first;
                write(sink, line(now, "WARN", "Container health check failed: " + result.reason() + " (" + result.words() + "); probe " + uri.getHost() + ":"
                        + uri.getPort() + uri.getPath() + ", " + failures + " failed in a row, down for " + downSeconds + " s"));
                lastLogged = now.getEpochSecond();
            }
            Files.writeString(state, result.reason() + " " + first + " " + lastLogged + " " + failures, StandardCharsets.US_ASCII);
        } catch (IOException | RuntimeException unwritable) {
            // The exit code is what ECS acts on; a log line that cannot be written must never change it.
        }
    }

    private static void write(Sink sink, String line) throws IOException {
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        try (OutputStream out = sink.open()) {
            out.write(bytes);  // one write: under PIPE_BUF it cannot interleave with the application's own lines
        } catch (IOException unreachable) {
            PrintStream err = System.err;
            err.write(bytes);
            err.flush();
        }
    }

    /**
     * One line in the application's own shape, "{@code 2026-11-04T20:00:00.000Z WARN  Container health check failed: …}".
     * No request bracket: the probe serves no request. Line breaks in the words become spaces so it stays one line.
     */
    static String line(Instant now, String level, String message) {
        return TIMESTAMP.format(now) + " " + String.format("%-5s", level) + " " + message.replaceAll("\\s*[\\r\\n\\t]+\\s*", " ");
    }

    /** Exception types only, e.g. "IOException < ClosedChannelException": messages are never written. */
    static String types(Throwable failure) {
        var names = new StringBuilder();
        for (Throwable at = failure; at != null && names.length() < 200; at = at.getCause())
            names.append(names.length() == 0 ? "" : " < ").append(at.getClass().getSimpleName());
        return names.toString();
    }
}
