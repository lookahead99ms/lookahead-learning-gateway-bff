package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.lookahead.gateway.config.UpstreamClientConfiguration;
import com.lookahead.gateway.config.UpstreamHttpConfiguration;
import com.lookahead.gateway.controller.DomainProxyController;
import com.lookahead.gateway.controller.SignInController;
import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import com.lookahead.gateway.security.config.OAuthConfiguration;
import com.lookahead.gateway.security.config.SecurityFilterChainConfiguration;
import com.lookahead.gateway.security.config.SignInFilterConfiguration;
import com.lookahead.gateway.security.config.SignInHandlerConfiguration;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestClientException;
import tools.jackson.databind.ObjectMapper;

/**
 * The two error answers of UpstreamErrorHandler, serialised by the application's own JSON mapper
 * (which is why the application context of the JSON wire-contract test,
 * ApiResponseJsonContractTest, is started here unchanged).
 */
@SpringBootTest(
    classes = UpstreamErrorHandlerIntegrationTest.Application.class,
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
class UpstreamErrorHandlerIntegrationTest {
  private static final String ACCESS_TOKEN = "synthetic-server-held-access-token";
  private final OAuthClientDetails oauth =
      new OAuthClientDetails(
          "http://127.0.0.1:4331",
          "lookahead-json-contract",
          "synthetic-client-secret-for-json-contract",
          "http://identity:8080",
          "http://domain-api:8080",
          "http://127.0.0.1:4331");

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
  void gatewayErrorsKeepStableCodesAndNeverSerializeUpstreamExceptionSecrets() {
    var handler = new UpstreamErrorHandler();
    // Plain logs: the failure is one ERROR line quoting the exception's message, with a bearer
    // credential in it masked.
    var upstream = (Logger) LoggerFactory.getLogger("lookahead.upstream");
    var errors = new ListAppender<ILoggingEvent>();
    errors.start();
    upstream.addAppender(errors);
    ResponseEntity<?> unavailable;
    try {
      unavailable =
          handler.unavailable(
              new RestClientException("Identity refused: Authorization: Bearer " + ACCESS_TOKEN),
              new MockHttpServletRequest("GET", "/bff/api/v1/me"));
    } finally {
      upstream.detachAppender(errors);
    }
    assertThat(errors.list).hasSize(1);
    assertThat(errors.list.getFirst().getLevel()).isEqualTo(Level.ERROR);
    assertThat(errors.list.getFirst().getFormattedMessage())
        .startsWith(
            "Outside a request: the upstream call for GET /bff/api/v1/me failed"
                + " (RestClientException: Identity refused: Authorization=[hidden]); reference ")
        .doesNotContain(ACCESS_TOKEN);
    var events = (Logger) LoggerFactory.getLogger("lookahead.event");
    var capture = new ListAppender<ILoggingEvent>();
    capture.start();
    events.addAppender(capture);
    ResponseEntity<?> expired;
    try {
      expired =
          handler.expired(
              new OAuth2AuthorizationException(
                  new OAuth2Error("invalid_grant", ACCESS_TOKEN, null)),
              new MockHttpServletRequest("GET", "/bff/api/v1/me"));
    } finally {
      events.detachAppender(capture);
    }
    // DLV-969: the expiry is logged with its stable reason and the OAuth code, never the provider's
    // description.
    assertThat(capture.list).hasSize(1);
    assertThat(capture.list.getFirst().getLevel()).isEqualTo(Level.WARN);
    assertThat(capture.list.getFirst().getFormattedMessage())
        .isEqualTo(
            "Session expired for GET /bff/api/v1/me: the provider refused to renew the sign-in"
                + " (invalid_grant); the person must sign in again")
        .doesNotContain(ACCESS_TOKEN);
    assertThat(capture.list.getFirst().getKeyValuePairs())
        .extracting(pair -> pair.key + "=" + pair.value)
        .contains(
            "event.action=sign-in.session",
            "event.outcome=refused",
            "reason=SESSION_EXPIRED",
            "oauth.code=invalid_grant");
    assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
    assertThat(expired.getStatusCode().value()).isEqualTo(401);
    for (var response : List.of(unavailable, expired)) {
      var serialized = mapper.writeValueAsString(response.getBody());
      assertThat(mapper.readTree(serialized).propertyNames())
          .containsExactlyInAnyOrder("code", "message");
      assertThat(serialized).doesNotContain(ACCESS_TOKEN, oauth.clientSecret(), "invalid_grant");
      assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
    }
    assertThat(mapper.valueToTree(unavailable.getBody()).path("code").asString())
        .isEqualTo("SERVICE_UNAVAILABLE");
    assertThat(mapper.valueToTree(expired.getBody()).path("code").asString())
        .isEqualTo("SESSION_EXPIRED");
  }
}
