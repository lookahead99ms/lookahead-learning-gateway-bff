package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

/** DLV-969: the attempt counter of the password pages, driven directly; the routes it slows are driven in PasswordSignInHandlerTest. */
class PasswordSignInThrottleTest {
    final MutableClock clock = new MutableClock(Instant.parse("2026-11-02T20:00:00Z"));
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }
    @Test void throttleForgetsOldKeysWhenItGrowsLarge() {
        var throttle = new PasswordSignInThrottle(clock);
        for (int i = 0; i <= PasswordSignInThrottle.MAX_KEYS; i++) throttle.allow("password", "198.51.100." + (i % 250), "user" + i + "@example.invalid");
        clock.advance(601);
        assertThat(throttle.allow("password", "198.51.100.1", "user1@example.invalid")).isTrue();
        assertThat(throttle.allow("password", null, null)).isTrue();
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
