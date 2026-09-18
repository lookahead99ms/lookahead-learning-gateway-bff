package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.assertThat;

class AuthorPreviewConfigurationTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(AuthorPreviewConfiguration.class, AuthorPreviewController.class)
            .withBean(OAuthSettings.class, () -> AuthorPreviewSettingsTest.OAUTH)
            .withBean(OAuthProperties.class, AuthorPreviewConfigurationTest::oauthProperties)
            .withBean(OAuth2AuthorizedClientManager.class, () -> request -> null)
            .withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=local",
                    "app.author-previews.upstream=http://127.0.0.1:4315",
                    "app.author-previews.upstream-secret=" + AuthorPreviewSettingsTest.SOURCE_SECRET);

    @Test void routeAndOutboundProxyAreAbsentByDefaultOrWhenExplicitlyDisabled() {
        runner.run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(AuthorPreviewController.class)
                .doesNotHaveBean(AuthorPreviewProxy.class).doesNotHaveBean(AuthorPreviewSettings.class));
        runner.withPropertyValues("app.author-previews.enabled=false").run(context -> assertThat(context)
                .hasNotFailed().doesNotHaveBean(AuthorPreviewController.class).doesNotHaveBean(AuthorPreviewProxy.class));
    }

    @Test void explicitLocalGatewayActivationCreatesTheGuardedRoute() {
        runner.withPropertyValues("app.author-previews.enabled=true").run(context -> assertThat(context)
                .hasNotFailed().hasSingleBean(AuthorPreviewController.class).hasSingleBean(AuthorPreviewProxy.class)
                .hasSingleBean(AuthorPreviewSettings.class));
        runner.withPropertyValues("app.author-previews.enabled=true", "spring.profiles.active=accounts,local-test,oauth-server")
                .run(context -> assertThat(context).hasNotFailed().doesNotHaveBean(AuthorPreviewController.class)
                        .doesNotHaveBean(AuthorPreviewProxy.class));
    }

    @Test void enabledPreviewFailsClosedOutsideExplicitLocalDeployment() {
        for (String setting : new String[]{"app.deployment-environment=prod", "app.deployment-environment=dev",
                "app.deployment-environment=", "spring.profiles.active=gateway,prod",
                "spring.profiles.active=gateway,production"}) {
            runner.withPropertyValues("app.author-previews.enabled=true", setting).run(context ->
                    assertThat(context).hasFailed());
        }
    }

    @Test void enabledPreviewRequiresItsOwnConfiguredSourceAndKey() {
        for (String setting : new String[]{"app.author-previews.upstream=", "app.author-previews.upstream=https://other.test",
                "app.author-previews.upstream-secret=", "app.author-previews.upstream-secret=short"}) {
            runner.withPropertyValues("app.author-previews.enabled=true", setting).run(context ->
                    assertThat(context).hasFailed());
        }
    }

    @Test void actualHttpTransportNeverFollowsApiOrArtifactRedirects() throws Exception {
        var http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var redirectApi = new AtomicBoolean(true);
        var artifactRequests = new AtomicInteger();
        var redirectTargetRequests = new AtomicInteger();
        http.createContext("/api/v1/author/previews/access", exchange -> {
            if (redirectApi.get()) {
                exchange.getResponseHeaders().set("Location", "/redirect-target");
                exchange.sendResponseHeaders(302, -1);
            } else {
                exchange.sendResponseHeaders(204, -1);
            }
            exchange.close();
        });
        http.createContext("/index.html", exchange -> {
            artifactRequests.incrementAndGet();
            exchange.getResponseHeaders().set("Location", "/redirect-target");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        http.createContext("/redirect-target", exchange -> {
            redirectTargetRequests.incrementAndGet();
            exchange.sendResponseHeaders(200, -1);
            exchange.close();
        });
        http.start();
        try {
            String origin = "http://127.0.0.1:" + http.getAddress().getPort();
            var oauth = AuthorPreviewSettingsTest.OAUTH;
            var proxy = new AuthorPreviewConfiguration().authorPreviewProxy(
                    new AuthorPreviewSettings(URI.create(origin), AuthorPreviewSettingsTest.SOURCE_SECRET),
                    new OAuthSettings(oauth.issuer(), oauth.clientId(), oauth.clientSecret(), oauth.identityUpstream(), origin, oauth.frontend()),
                    oauthProperties());
            assertThat(proxy.fetch("GET", AuthorPreviewPath.PREFIX + "index.html", null, "synthetic-token")
                    .getStatusCode().value()).isEqualTo(503);
            assertThat(artifactRequests.get()).isZero();
            assertThat(redirectTargetRequests.get()).isZero();
            redirectApi.set(false);
            assertThat(proxy.fetch("GET", AuthorPreviewPath.PREFIX + "index.html", null, "synthetic-token")
                    .getStatusCode().value()).isEqualTo(502);
            assertThat(artifactRequests.get()).isEqualTo(1);
            assertThat(redirectTargetRequests.get()).isZero();
        } finally {
            http.stop(0);
        }
    }

    private static OAuthProperties oauthProperties() {
        var settings = AuthorPreviewSettingsTest.OAUTH;
        return new OAuthProperties(settings.issuer(), settings.frontend(), settings.clientSecret(), settings.clientId(),
                settings.identityUpstream(), settings.domainApiUpstream(), Duration.ofSeconds(3), Duration.ofSeconds(7));
    }
}
