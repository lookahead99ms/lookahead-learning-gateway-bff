package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthPropertiesConfiguration;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import static org.assertj.core.api.Assertions.assertThat;

/** DLV-914: the running Gateway reports its release through /actuator/info and exposes nothing else new. */
@SpringBootTest(classes = ActuatorInfoReleaseTest.Application.class, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=actuator-info-release-test", "server.address=127.0.0.1", "app.deployment-environment=local",
                "app.oauth.issuer=http://127.0.0.1:4331", "app.oauth.frontend=http://127.0.0.1:4331",
                "app.oauth.client-secret=synthetic-long-client-secret-for-testing", "app.oauth.client-id=lookahead-test-gateway",
                "app.oauth.identity-upstream=http://identity:8080", "app.oauth.domain-api-upstream=http://domain-api:8080",
                // Same exposure as application.yml (asserted below); the real file needs deployment secrets.
                "management.endpoints.web.exposure.include=health,info"})
@ActiveProfiles("gateway")
class ActuatorInfoReleaseTest {
    @Configuration
    @EnableAutoConfiguration(excludeName = {"org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @Import({ActiveSignInTestConfiguration.class, GatewayConfiguration.class, GatewayClientConfiguration.class,
            OAuthPropertiesConfiguration.class, GatewayController.class})
    static class Application { }

    @LocalServerPort int port;
    private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    private HttpResponse<String> send(String method, String path) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path)).method(method, HttpRequest.BodyPublishers.noBody()).build();
        return client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    @Test void infoReportsBuildVersionReleaseTagAndSourceRevisionWithoutAuthentication() throws Exception {
        var response = send("GET", "/actuator/info");
        assertThat(response.statusCode()).isEqualTo(200);
        JsonNode build = new ObjectMapper().readTree(response.body()).path("build");
        // Gradle receives -PreleaseVersion (calendar version in a release build, 0.0.1-SNAPSHOT otherwise) plus tag and commit.
        assertThat(build.path("version").asString()).matches("\\d{4}\\.\\d{2}\\.\\d{2}\\.\\d{2}\\.\\d+|0\\.0\\.1-SNAPSHOT");
        assertThat(build.path("name").asString()).isEqualTo("lookahead-learning-gateway-bff");
        assertThat(build.path("releaseTag").asString()).matches("v\\d{4}\\.\\d{2}\\.\\d{2}\\.\\d{2}\\.\\d+|dev");
        assertThat(build.path("sourceRevision").asString()).matches("[a-f0-9]{40}|local");
        if (!"dev".equals(build.path("releaseTag").asString()))
            assertThat(build.path("releaseTag").asString()).isEqualTo("v" + build.path("version").asString());
        assertThat(response.body()).doesNotContain("secret").doesNotContain("password");
    }

    @Test void noOtherActuatorEndpointBecamePublic() throws Exception {
        for (String path : List.of("/actuator", "/actuator/env", "/actuator/beans", "/actuator/mappings", "/actuator/loggers",
                "/actuator/configprops", "/actuator/metrics", "/actuator/threaddump", "/actuator/heapdump", "/actuator/conditions"))
            assertThat(send("GET", path).statusCode()).as(path).isIn(401, 403, 404);
        assertThat(send("POST", "/actuator/info").statusCode()).isNotEqualTo(200);
        assertThat(send("GET", "/actuator/health").statusCode()).isEqualTo(200);
    }

    @Test void applicationConfigurationExposesOnlyHealthAndInfo() throws IOException {
        String yaml = Files.readString(Path.of("src/main/resources/application.yml"));
        assertThat(yaml).contains("management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\n");
        assertThat(yaml.split("exposure:").length - 1).isEqualTo(1);
    }
}
