package com.lookahead.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import com.lookahead.gateway.config.UpstreamClientConfiguration;
import com.lookahead.gateway.config.UpstreamHttpConfiguration;
import com.lookahead.gateway.controller.DomainProxyController;
import com.lookahead.gateway.controller.SignInController;
import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import com.lookahead.gateway.security.config.OAuthConfiguration;
import com.lookahead.gateway.security.config.SecurityFilterChainConfiguration;
import com.lookahead.gateway.security.config.SignInFilterConfiguration;
import com.lookahead.gateway.security.config.SignInHandlerConfiguration;
import com.lookahead.gateway.security.handler.UpstreamErrorHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
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
import org.springframework.test.context.ActiveProfiles;
import tools.jackson.databind.ObjectMapper;

/** Wire contracts remain stable when transport types are owned by this application. */
@SpringBootTest(
    classes = ApiResponseJsonContractTest.Application.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    properties = {
      "spring.config.name=json-contract-test",
      "app.deployment-environment=local",
      "app.oauth.issuer=http://127.0.0.1:4331",
      "app.oauth.frontend=http://127.0.0.1:4331",
      "app.oauth.client-secret=synthetic-client-secret-for-json-contract",
      "app.oauth.client-id=lookahead-json-contract",
      "app.oauth.identity-upstream=http://identity:8080",
      "app.oauth.domain-api-upstream=http://domain-api:8080"
    })
@ActiveProfiles("gateway")
class ApiResponseJsonContractTest {
  private static final Instant TIMESTAMP = Instant.parse("2026-09-18T00:00:00Z");
  private final OAuthClientDetails oauth =
      new OAuthClientDetails(
          "http://127.0.0.1:4331",
          "lookahead-json-contract",
          "synthetic-client-secret-for-json-contract",
          "http://identity:8080",
          "http://domain-api:8080",
          "http://127.0.0.1:4331");

  @LocalServerPort int port;
  @Autowired ObjectMapper mapper;

  @Configuration
  @EnableAutoConfiguration
  @Import({
    SecurityFilterChainConfiguration.class,
    OAuthClientConfiguration.class,
    UpstreamHttpConfiguration.class,
    UpstreamClientConfiguration.class,
    OAuthConfiguration.class,
    SignInHandlerConfiguration.class,
    SignInFilterConfiguration.class,
    SignInController.class,
    DomainProxyController.class,
    UpstreamErrorHandler.class
  })
  static class Application {}

  @Test
  void browserCsrfResponsePreservesNamesTimestampAndCredentialBoundary() throws Exception {
    var response =
        HttpClient.newHttpClient()
            .send(
                HttpRequest.newBuilder(
                        URI.create("http://127.0.0.1:" + port + "/bff/api/v1/auth/csrf"))
                    .GET()
                    .build(),
                HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.headers().firstValue("cache-control")).contains("no-store");
    var json = mapper.readTree(response.body());
    assertThat(json.propertyNames()).containsExactlyInAnyOrder("data", "timestamp");
    assertThat(json.path("data").propertyNames())
        .containsExactlyInAnyOrder("token", "headerName", "parameterName");
    assertThat(json.path("data").path("token").asString()).isNotBlank();
    assertThat(json.path("data").path("headerName").asString()).isEqualTo("X-CSRF-TOKEN");
    assertThat(json.path("data").path("parameterName").asString()).isEqualTo("_csrf");
    assertThat(Instant.parse(json.path("timestamp").asString())).isBeforeOrEqualTo(Instant.now());
    assertThat(response.body())
        .doesNotContain("access_token", "refresh_token", "client_secret", oauth.clientSecret());
  }

  @Test
  void historicalEnvelopeDeserializesWithMissingAndExplicitNullFields() {
    var type = mapper.getTypeFactory().constructParametricType(ApiResponse.class, CsrfView.class);
    ApiResponse<CsrfView> legacy =
        mapper.readValue(
            """
            {"data":{"token":"synthetic-csrf","headerName":"X-CSRF-TOKEN","parameterName":"_csrf"},
             "timestamp":"2026-09-18T00:00:00Z"}
            """,
            type);
    assertThat(legacy)
        .isEqualTo(
            new ApiResponse<>(new CsrfView("synthetic-csrf", "X-CSRF-TOKEN", "_csrf"), TIMESTAMP));
    for (String json : List.of("{}", "{\"data\":null,\"timestamp\":null}")) {
      ApiResponse<CsrfView> empty = mapper.readValue(json, type);
      assertThat(empty.data()).isNull();
      assertThat(empty.timestamp()).isNull();
    }
    assertThat(mapper.readValue("{\"token\":null}", CsrfView.class))
        .isEqualTo(new CsrfView(null, null, null));
  }

  @Test
  void nullDataAndLogoutEnvelopeKeepTheirPublishedShape() {
    assertThat(mapper.readTree(mapper.writeValueAsString(new ApiResponse<>(null, TIMESTAMP))))
        .isEqualTo(mapper.readTree("{\"data\":null,\"timestamp\":\"2026-09-18T00:00:00Z\"}"));
    var logout =
        mapper.readTree(
            mapper.writeValueAsString(
                new ApiResponse<>(
                    Map.of(
                        "logoutUrl",
                        "http://127.0.0.1:4331/connect/logout?post_logout_redirect_uri=synthetic"),
                    TIMESTAMP)));
    assertThat(logout.propertyNames()).containsExactlyInAnyOrder("data", "timestamp");
    assertThat(logout.path("data").propertyNames()).containsExactly("logoutUrl");
  }
}
