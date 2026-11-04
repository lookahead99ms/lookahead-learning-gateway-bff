package com.lookahead.gateway;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * DLV-969 (owner, 2026-11-04): a start the Gateway refuses says which setting, secret or file was wrong, by NAME, before
 * Spring Boot's own "Application run failed" line. One WARN on {@code lookahead.lifecycle} with {@code event.action}
 * {@code startup.refused}, the {@code setting} (property and the variable that sets it) and a stable {@code reason}.
 * Never the value: settings hold secrets, certificates, keys and internal URLs.
 */
public final class StartupLog {
    public static final Logger LIFECYCLE = LoggerFactory.getLogger("lookahead.lifecycle");

    private StartupLog() {}

    /**
     * Logs the refusal and returns the exception to throw. {@code message} is the caller's fixed text (never a value) and
     * stays the exception's message, so existing messages and their checks are unchanged.
     */
    public static IllegalStateException refused(String setting, String reason, String message) {
        LIFECYCLE.atWarn().addKeyValue("event.action", "startup.refused").addKeyValue("event.outcome", "failure")
                .addKeyValue("setting", setting).addKeyValue("reason", reason)
                .log("Startup refused: {} {} ({}): {}; the Gateway will not start", setting, words(reason), reason, message);
        return new IllegalStateException(message);
    }

    /** The reason in words for the common codes; any other code is already descriptive. */
    static String words(String reason) {
        return switch (reason) {
            case "MISSING" -> "is missing or empty";
            case "INVALID" -> "is set but not valid";
            case "NOT_ALLOWED" -> "is not allowed in this deployment";
            default -> "was rejected";
        };
    }
}
