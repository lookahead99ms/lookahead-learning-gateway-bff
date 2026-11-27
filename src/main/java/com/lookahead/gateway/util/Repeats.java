package com.lookahead.gateway.util;

import java.time.Duration;
import java.util.function.LongSupplier;

/**
 * For a line on a hot path (a polled route, every request): due when the key changes, then at most once per
 * {@code every} while it stays the same. {@link #clear} after recovery so the next failure logs at once.
 */
public final class Repeats {
    private final long everyNanos;
    private final LongSupplier clock;
    private String last;
    private long at;
    public Repeats(Duration every) { this(every, System::nanoTime); }
    public Repeats(Duration every, LongSupplier clock) { this.everyNanos = every.toNanos(); this.clock = clock; }
    public synchronized boolean due(String key) {
        long now = clock.getAsLong();
        if (key.equals(last) && now - at < everyNanos) return false;
        last = key; at = now;
        return true;
    }
    public synchronized void clear() { last = null; }
}
