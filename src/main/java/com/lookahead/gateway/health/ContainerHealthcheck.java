package com.lookahead.gateway.health;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/** Container readiness probe using only the Java runtime already in the image. */
public final class ContainerHealthcheck {
    static final URI READINESS_URI = URI.create("http://127.0.0.1:8080/actuator/health/readiness");
    /** The lower-cost DEV profile serves actuator only on its loopback management port 8081 (application-lower-cost-dev.yml). */
    static final URI MANAGEMENT_READINESS_URI = URI.create("http://127.0.0.1:8081/actuator/health/readiness");

    private ContainerHealthcheck() {
    }

    public static void main(String[] args) {
        System.exit(check(readinessUri(System.getenv("LOOKAHEAD_RUNTIME_MODE"))));
    }

    /** ECS sets LOOKAHEAD_RUNTIME_MODE=lower-cost-dev; every other mode keeps the container port 8080 probe. */
    static URI readinessUri(String runtimeMode) {
        return "lower-cost-dev".equals(runtimeMode) ? MANAGEMENT_READINESS_URI : READINESS_URI;
    }

    static int check(URI readinessUri) {
        return check(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build(), readinessUri);
    }

    static int check(HttpClient client, URI readinessUri) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(readinessUri)
                    .timeout(Duration.ofSeconds(3))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() == 200
                    && response.body().matches("\\s*\\{\\s*\"status\"\\s*:\\s*\"UP\"\\s*}\\s*") ? 0 : 1;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            return 1;
        } catch (Exception exception) {
            return 1;
        }
    }
}
