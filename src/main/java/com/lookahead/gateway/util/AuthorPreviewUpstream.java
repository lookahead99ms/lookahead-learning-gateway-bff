package com.lookahead.gateway.util;

import java.net.URI;
import java.util.Arrays;
import java.util.Set;
import org.springframework.core.env.Environment;

/** Local deployment configuration; browser input never selects the artifact server. */
public record AuthorPreviewUpstream(URI upstream, String upstreamSecret) {
  public static AuthorPreviewUpstream from(Environment environment, String frontendOrigin) {
    boolean production =
        Arrays.stream(environment.getActiveProfiles())
            .anyMatch(profile -> Set.of("prod", "production").contains(profile));
    URI frontend = URI.create(frontendOrigin);
    if (!"local".equals(environment.getProperty("app.deployment-environment"))
        || production
        || frontend.getHost() == null
        || !Set.of("127.0.0.1", "localhost").contains(frontend.getHost())) {
      throw new IllegalStateException(
          "Author previews require an explicit local deployment and loopback frontend");
    }
    URI upstream;
    try {
      upstream = URI.create(environment.getRequiredProperty("app.author-previews.upstream"));
    } catch (IllegalArgumentException error) {
      throw new IllegalStateException("Author preview upstream must be a configured local origin");
    }
    String host = upstream.getHost();
    if (!"http".equals(upstream.getScheme())
        || host == null
        || !Set.of("127.0.0.1", "host.docker.internal").contains(host)
        || upstream.getPort() != 4315
        || upstream.getRawUserInfo() != null
        || upstream.getRawQuery() != null
        || upstream.getRawFragment() != null
        || !(upstream.getRawPath().isEmpty() || upstream.getRawPath().equals("/"))) {
      throw new IllegalStateException(
          "Author preview upstream must be the fixed local preview origin on port 4315");
    }
    String secret = environment.getRequiredProperty("app.author-previews.upstream-secret");
    if (!secret.matches("[A-Za-z0-9_-]{32,256}")) {
      throw new IllegalStateException(
          "Author preview source key must contain 32 to 256 URL-safe characters");
    }
    return new AuthorPreviewUpstream(URI.create("http://" + host + ":4315"), secret);
  }

  @Override
  public String toString() {
    return "AuthorPreviewUpstream[redacted]";
  }
}
