package com.lookahead.learning.content.gateway;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * DLV-969: slows down repeated attempts on our own password pages. In-memory and per Gateway task, so each running task
 * counts on its own; Cognito's own per-user lockout stays the account-level protection behind it.
 */
final class PasswordSignInThrottle {
    static final int PER_ADDRESS = 30;
    static final int PER_ACCOUNT = 10;
    static final Duration WINDOW = Duration.ofMinutes(10);
    static final int MAX_KEYS = 10_000;
    private final Clock clock;
    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();

    PasswordSignInThrottle(Clock clock) { this.clock = clock; }

    /** Records one attempt; false when the address or the account has used its allowance in the window. */
    boolean allow(String address, String account) { return allow("password", address, account); }

    /**
     * As {@link #allow(String, String)}; a refusal writes one {@code lookahead.limit} WARN line per limit reached, naming
     * the limit (per address or per account), its size and window and the page {@code action}. Never the address or account.
     */
    boolean allow(String action, String address, String account) {
        if (attempts.size() > MAX_KEYS) prune();
        boolean byAddress = record("ip:" + (address == null ? "" : address), PER_ADDRESS);
        boolean byAccount = account == null || account.isBlank() || record("user:" + account.strip().toLowerCase(Locale.ROOT), PER_ACCOUNT);
        if (!byAddress) OpsLog.limit("password-pages.per-address", PER_ADDRESS, WINDOW, action,
                "Rate limit reached: {} refused, more than {} password-page attempts from one address in {} minutes",
                action, PER_ADDRESS, WINDOW.toMinutes());
        if (!byAccount) OpsLog.limit("password-pages.per-account", PER_ACCOUNT, WINDOW, action,
                "Rate limit reached: {} refused, more than {} password-page attempts for one account in {} minutes",
                action, PER_ACCOUNT, WINDOW.toMinutes());
        return byAddress && byAccount;
    }

    private boolean record(String key, int limit) {
        Instant now = clock.instant(), cutoff = now.minus(WINDOW);
        var queue = attempts.computeIfAbsent(key, k -> new ArrayDeque<>());
        synchronized (queue) {
            while (!queue.isEmpty() && !queue.peekFirst().isAfter(cutoff)) queue.pollFirst();
            if (queue.size() >= limit) return false;
            queue.addLast(now);
            return true;
        }
    }

    private void prune() {
        Instant cutoff = clock.instant().minus(WINDOW);
        attempts.entrySet().removeIf(entry -> {
            synchronized (entry.getValue()) {
                return entry.getValue().isEmpty() || !entry.getValue().peekLast().isAfter(cutoff);
            }
        });
    }
}
