package com.lookahead.gateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.lookahead.gateway.client.AuthorPreviewDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.controller.AuthorPreviewController;
import com.lookahead.gateway.proxy.AuthorPreviewProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.AuthorPreviewPath;
import com.lookahead.gateway.util.AuthorPreviewUpstream;
import com.lookahead.gateway.util.AuthorPreviewUpstreamTest;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

class AuthorPreviewConfigurationTest {
  private final ApplicationContextRunner runner =
      new ApplicationContextRunner()
          .withUserConfiguration(AuthorPreviewConfiguration.class, AuthorPreviewController.class)
          .withBean(OAuthClientDetails.class, () -> AuthorPreviewUpstreamTest.OAUTH)
          .withBean(OAuthConfigValues.class, AuthorPreviewConfigurationTest::oauthConfigValues)
          .withBean(SignInTokenClient.class, () -> new SignInTokenClient(request -> null))
          .withPropertyValues(
              "spring.profiles.active=gateway",
              "app.deployment-environment=local",
              "app.author-previews.upstream=http://127.0.0.1:4315",
              "app.author-previews.upstream-secret=" + AuthorPreviewUpstreamTest.SOURCE_SECRET);

  @Test
  void routeAndOutboundProxyAreAbsentByDefaultOrWhenExplicitlyDisabled() {
    runner.run(context ->
        assertThat(context)
            .hasNotFailed()
            .doesNotHaveBean(AuthorPreviewController.class)
            .doesNotHaveBean(AuthorPreviewProxy.class)
            .doesNotHaveBean(AuthorPreviewUpstream.class));
    runner
        .withPropertyValues("app.author-previews.enabled=false")
        .run(context ->
            assertThat(context)
                .hasNotFailed()
                .doesNotHaveBean(AuthorPreviewController.class)
                .doesNotHaveBean(AuthorPreviewProxy.class));
  }

  @Test
  void explicitLocalGatewayActivationCreatesTheGuardedRoute() {
    runner
        .withPropertyValues("app.author-previews.enabled=true")
        .run(context ->
            assertThat(context)
                .hasNotFailed()
                .hasSingleBean(AuthorPreviewController.class)
                .hasSingleBean(AuthorPreviewProxy.class)
                .hasSingleBean(AuthorPreviewUpstream.class));
    runner
        .withPropertyValues(
            "app.author-previews.enabled=true",
            "spring.profiles.active=accounts,local-test,oauth-server")
        .run(context ->
            assertThat(context)
                .hasNotFailed()
                .doesNotHaveBean(AuthorPreviewController.class)
                .doesNotHaveBean(AuthorPreviewProxy.class));
  }

  /**
   * DLV-1015: the Domain's access check and the artifact fetch still leave on one and the same
   * connection.
   */
  @Test
  void theAccessCheckAndTheArtifactFetchShareTheOneAuthorPreviewConnection() {
    runner
        .withPropertyValues("app.author-previews.enabled=true")
        .withBean("upstreamHttp", RestClient.class, RestClient::create)
        .withBean(GeneralCaller.class)
        .run(context -> {
          assertThat(context)
              .hasNotFailed()
              .hasSingleBean(AuthorPreviewDomainClient.class)
              .hasBean("authorPreviewHttp")
              .hasBean("authorPreviewDomainClient")
              .hasBean("authorPreviewProxy");
          Object connection = context.getBean("authorPreviewHttp");
          assertThat(
                  ReflectionTestUtils.getField(context.getBean(AuthorPreviewProxy.class), "http"))
              .isSameAs(connection);
          assertThat(
                  ReflectionTestUtils.getField(
                      context.getBean(AuthorPreviewDomainClient.class), "http"))
              .isSameAs(connection);
          assertThat(
                  ReflectionTestUtils.getField(context.getBean(AuthorPreviewProxy.class), "domain"))
              .isSameAs(context.getBean(AuthorPreviewDomainClient.class));
          // A plain RestClient parameter anywhere else still receives the general connection, never
          // this one.
          assertThat(context.getBean(GeneralCaller.class).http)
              .isSameAs(context.getBean("upstreamHttp"))
              .isNotSameAs(connection);
        });
    runner.run(context ->
        assertThat(context)
            .hasNotFailed()
            .doesNotHaveBean("authorPreviewHttp")
            .doesNotHaveBean(AuthorPreviewDomainClient.class));
  }

  static final class GeneralCaller {
    final RestClient http;

    GeneralCaller(RestClient http) {
      this.http = http;
    }
  }

  @Test
  void enabledPreviewFailsClosedOutsideExplicitLocalDeployment() {
    for (String setting :
        new String[] {
          "app.deployment-environment=prod",
          "app.deployment-environment=dev",
          "app.deployment-environment=",
          "spring.profiles.active=gateway,prod",
          "spring.profiles.active=gateway,production"
        }) {
      runner
          .withPropertyValues("app.author-previews.enabled=true", setting)
          .run(context -> assertThat(context).hasFailed());
    }
  }

  @Test
  void enabledPreviewRequiresItsOwnConfiguredSourceAndKey() {
    for (String setting :
        new String[] {
          "app.author-previews.upstream=",
          "app.author-previews.upstream=https://other.test",
          "app.author-previews.upstream-secret=",
          "app.author-previews.upstream-secret=short"
        }) {
      runner
          .withPropertyValues("app.author-previews.enabled=true", setting)
          .run(context -> assertThat(context).hasFailed());
    }
  }

  @Test
  void actualHttpTransportNeverFollowsApiOrArtifactRedirects() throws Exception {
    var http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    var redirectApi = new AtomicBoolean(true);
    var artifactRequests = new AtomicInteger();
    var redirectTargetRequests = new AtomicInteger();
    http.createContext(
        "/api/v1/author/previews/access",
        exchange -> {
          if (redirectApi.get()) {
            exchange.getResponseHeaders().set("Location", "/redirect-target");
            exchange.sendResponseHeaders(302, -1);
          } else {
            exchange.sendResponseHeaders(204, -1);
          }
          exchange.close();
        });
    http.createContext(
        "/index.html",
        exchange -> {
          artifactRequests.incrementAndGet();
          exchange.getResponseHeaders().set("Location", "/redirect-target");
          exchange.sendResponseHeaders(302, -1);
          exchange.close();
        });
    http.createContext(
        "/redirect-target",
        exchange -> {
          redirectTargetRequests.incrementAndGet();
          exchange.sendResponseHeaders(200, -1);
          exchange.close();
        });
    http.start();
    try {
      String origin = "http://127.0.0.1:" + http.getAddress().getPort();
      var oauth = AuthorPreviewUpstreamTest.OAUTH;
      var configuration = new AuthorPreviewConfiguration();
      var connection = configuration.authorPreviewHttp(oauthConfigValues());
      var proxy =
          configuration.authorPreviewProxy(
              new AuthorPreviewUpstream(
                  URI.create(origin), AuthorPreviewUpstreamTest.SOURCE_SECRET),
              configuration.authorPreviewDomainClient(
                  new OAuthClientDetails(
                      oauth.issuer(),
                      oauth.clientId(),
                      oauth.clientSecret(),
                      oauth.identityUpstream(),
                      origin,
                      oauth.frontend()),
                  connection),
              new SignInTokenClient(request -> null),
              connection);
      assertThat(
              proxy
                  .fetch(
                      "GET", AuthorPreviewPath.PREFIX + "index.html", null, "synthetic-token", null)
                  .getStatusCode()
                  .value())
          .isEqualTo(503);
      assertThat(artifactRequests.get()).isZero();
      assertThat(redirectTargetRequests.get()).isZero();
      redirectApi.set(false);
      assertThat(
              proxy
                  .fetch(
                      "GET", AuthorPreviewPath.PREFIX + "index.html", null, "synthetic-token", null)
                  .getStatusCode()
                  .value())
          .isEqualTo(502);
      assertThat(artifactRequests.get()).isEqualTo(1);
      assertThat(redirectTargetRequests.get()).isZero();
    } finally {
      http.stop(0);
    }
  }

  private static OAuthConfigValues oauthConfigValues() {
    var oauth = AuthorPreviewUpstreamTest.OAUTH;
    return new OAuthConfigValues(
        oauth.issuer(),
        oauth.frontend(),
        oauth.clientSecret(),
        oauth.clientId(),
        oauth.identityUpstream(),
        oauth.domainApiUpstream(),
        Duration.ofSeconds(3),
        Duration.ofSeconds(7));
  }
}
