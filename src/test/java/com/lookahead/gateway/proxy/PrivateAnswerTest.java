package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;

class PrivateAnswerTest {
    @Test void theEmptyAnswerHasTheStatusNoBodyAndTheHeadersThatKeepItPrivate() {
        for (int status : new int[] {400, 401, 404, 405, 502, 503}) {
            var answer = PrivateAnswer.empty(status);
            assertThat(answer.getStatusCode().value()).isEqualTo(status);
            assertThat(answer.getBody()).isEmpty();
            assertThat(answer.getHeaders().toSingleValueMap()).containsOnly(
                    Map.entry("Cache-Control", "private, no-store"),
                    Map.entry("X-Content-Type-Options", "nosniff"),
                    Map.entry("Referrer-Policy", "no-referrer"),
                    Map.entry("X-Frame-Options", "DENY"),
                    Map.entry("Content-Security-Policy", "frame-ancestors 'none'"));
        }
    }

    @Test void everyCallStartsFromFreshHeaders() {
        var first = PrivateAnswer.responseHeaders();
        first.set("Content-Type", "text/html");
        assertThat(PrivateAnswer.responseHeaders().getContentType()).isNull();
        assertThat(PrivateAnswer.empty(401).getHeaders().getContentType()).isNull();
    }
}
