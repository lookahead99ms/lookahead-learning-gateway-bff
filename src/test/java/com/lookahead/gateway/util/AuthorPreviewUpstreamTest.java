package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

public class AuthorPreviewUpstreamTest {
  public static final String SOURCE_SECRET = "synthetic-preview-source-key-0123456789";
  public static final OAuthClientDetails OAUTH =
      new OAuthClientDetails(
          "http://127.0.0.1:4301",
          "lookahead-web-gateway-dev",
          "synthetic-oauth-client-secret-0123456789",
          "http://identity:8080",
          "http://domain-api:8080",
          "http://127.0.0.1:4301");

  @Test
  void acceptsOnlyTheNativeOrContainerLocalSourceAndRedactsItsKey() {
    for (String origin :
        new String[] {"http://127.0.0.1:4315", "http://host.docker.internal:4315/"}) {
      var upstream =
          AuthorPreviewUpstream.from(
              environment().withProperty("app.author-previews.upstream", origin), OAUTH.frontend());
      assertThat(upstream.upstream().toString()).isEqualTo(origin.replaceAll("/$", ""));
      assertThat(upstream.upstreamSecret()).isEqualTo(SOURCE_SECRET);
      assertThat(upstream.toString()).doesNotContain(SOURCE_SECRET).contains("redacted");
    }
  }

  @Test
  void rejectsProductionAndNonlocalDeploymentsOrFrontends() {
    for (String deployment : new String[] {"prod", "production", "dev", ""}) {
      assertThatIllegalStateException()
          .isThrownBy(() ->
              AuthorPreviewUpstream.from(
                  environment().withProperty("app.deployment-environment", deployment),
                  OAUTH.frontend()));
    }
    var missing = environment();
    missing.getPropertySources().remove("mockProperties");
    assertThatIllegalStateException()
        .isThrownBy(() -> AuthorPreviewUpstream.from(missing, OAUTH.frontend()));
    for (String profile : new String[] {"prod", "production"}) {
      var environment = environment();
      environment.setActiveProfiles("gateway", profile);
      assertThatIllegalStateException()
          .isThrownBy(() -> AuthorPreviewUpstream.from(environment, OAUTH.frontend()));
    }
    assertThatIllegalStateException()
        .isThrownBy(
            () -> AuthorPreviewUpstream.from(environment(), "https://preview.example.test"));
  }

  @Test
  void rejectsExternalOrAmbiguousUpstreamsAndInvalidKeys() {
    for (String origin :
        new String[] {
          "https://127.0.0.1:4315",
          "http://localhost:4315",
          "http://127.0.0.2:4315",
          "http://other.test:4315",
          "http://127.0.0.1:4316",
          "http://127.0.0.1",
          "http://[::1]:4315",
          "http://user@127.0.0.1:4315",
          "http://127.0.0.1:4315/private",
          "http://127.0.0.1:4315?target=x",
          "http://127.0.0.1:4315#fragment",
          "not a uri"
        }) {
      assertThatIllegalStateException()
          .as(origin)
          .isThrownBy(() ->
              AuthorPreviewUpstream.from(
                  environment().withProperty("app.author-previews.upstream", origin),
                  OAUTH.frontend()));
    }
    for (String key :
        new String[] {
          "", "a".repeat(31), "a".repeat(257), "a".repeat(32) + "\n", "a".repeat(32) + "/"
        }) {
      assertThatIllegalStateException()
          .isThrownBy(() ->
              AuthorPreviewUpstream.from(
                  environment().withProperty("app.author-previews.upstream-secret", key),
                  OAUTH.frontend()));
    }
  }

  private static MockEnvironment environment() {
    return new MockEnvironment()
        .withProperty("app.deployment-environment", "local")
        .withProperty("app.author-previews.upstream", "http://127.0.0.1:4315")
        .withProperty("app.author-previews.upstream-secret", SOURCE_SECRET);
  }
}
