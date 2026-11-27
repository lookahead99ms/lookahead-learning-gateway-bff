package com.lookahead.gateway.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** The bound {@code app.oauth} values: both HTTP timeouts must be inside their range, and the text form shows no value. */
class OAuthConfigValuesTest {
    static OAuthConfigValues values(Duration connectTimeout, Duration readTimeout) {
        return new OAuthConfigValues("http://127.0.0.1:4350", "http://127.0.0.1:4350", "synthetic-gateway-secret-never-used-outside-test",
                "lookahead-candidate", "http://identity:8080", "http://domain-api:8080", connectTimeout, readTimeout);
    }

    @Test void timeoutsOutsideTheSupportedRangeAreRefused() {
        Duration connect = Duration.ofSeconds(3), read = Duration.ofSeconds(7);
        for (Duration[] wrong : new Duration[][] {{null, read}, {connect, null}, {Duration.ofMillis(99), read}, {connect, Duration.ofMillis(99)},
                {Duration.ofSeconds(10).plusMillis(1), read}, {connect, Duration.ofSeconds(30).plusMillis(1)}})
            assertThatIllegalStateException().isThrownBy(() -> values(wrong[0], wrong[1])).withMessage("Gateway HTTP timeout outside supported range");
        assertThat(values(Duration.ofMillis(100), Duration.ofMillis(100)).connectTimeout()).isEqualTo(Duration.ofMillis(100));
        assertThat(values(Duration.ofSeconds(10), Duration.ofSeconds(30)).readTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test void textFormShowsNoValue() {
        assertThat(values(Duration.ofSeconds(3), Duration.ofSeconds(7)).toString()).isEqualTo("OAuthConfigValues[redacted]");
    }
}
