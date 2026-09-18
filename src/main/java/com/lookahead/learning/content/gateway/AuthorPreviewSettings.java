package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.springframework.core.env.Environment;
import java.net.URI;
import java.util.Arrays;
import java.util.Set;

/** Local deployment configuration; browser input never selects the artifact server. */
record AuthorPreviewSettings(URI upstream, String upstreamSecret) {
    static AuthorPreviewSettings from(Environment environment, OAuthSettings oauth) {
        boolean production = Arrays.stream(environment.getActiveProfiles())
                .anyMatch(profile -> Set.of("prod", "production").contains(profile));
        URI frontend = URI.create(oauth.frontend());
        if (!"local".equals(environment.getProperty("app.deployment-environment")) || production
                || frontend.getHost() == null || !Set.of("127.0.0.1", "localhost").contains(frontend.getHost())) {
            throw new IllegalStateException("Author previews require an explicit local deployment and loopback frontend");
        }
        URI upstream;
        try {
            upstream = URI.create(environment.getRequiredProperty("app.author-previews.upstream"));
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("Author preview upstream must be a configured local origin");
        }
        String host = upstream.getHost();
        if (!"http".equals(upstream.getScheme()) || host == null
                || !Set.of("127.0.0.1", "host.docker.internal").contains(host) || upstream.getPort() != 4315
                || upstream.getRawUserInfo() != null || upstream.getRawQuery() != null || upstream.getRawFragment() != null
                || !(upstream.getRawPath().isEmpty() || upstream.getRawPath().equals("/"))) {
            throw new IllegalStateException("Author preview upstream must be the fixed local preview origin on port 4315");
        }
        String secret = environment.getRequiredProperty("app.author-previews.upstream-secret");
        if (!secret.matches("[A-Za-z0-9_-]{32,256}")) {
            throw new IllegalStateException("Author preview source key must contain 32 to 256 URL-safe characters");
        }
        return new AuthorPreviewSettings(URI.create("http://" + host + ":4315"), secret);
    }

    @Override public String toString() { return "AuthorPreviewSettings[redacted]"; }
}
