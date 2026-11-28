package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

/**
 * The limiter for a line on a hot path: due when the key changes, then once per interval, and at
 * once after {@code clear}.
 */
class RepeatsTest {
  @Test
  void repeatsAreDueOnChangeAndOnceAMinute() {
    var clock = new AtomicLong();
    var repeats = new Repeats(Duration.ofMinutes(1), clock::get);
    assertThat(repeats.due("A")).isTrue();
    clock.addAndGet(Duration.ofSeconds(59).toNanos());
    assertThat(repeats.due("A")).isFalse();
    assertThat(repeats.due("B")).isTrue();
    clock.addAndGet(Duration.ofSeconds(60).toNanos());
    assertThat(repeats.due("B")).isTrue();
    repeats.clear();
    assertThat(repeats.due("B")).isTrue();
    assertThat(new Repeats(Duration.ofSeconds(1)).due("x")).isTrue();
  }
}
