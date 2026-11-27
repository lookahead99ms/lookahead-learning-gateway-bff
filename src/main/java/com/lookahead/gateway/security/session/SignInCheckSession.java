package com.lookahead.gateway.security.session;

import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.web.util.WebUtils;

/**
 * DLV-969 S37: the passed sign-in check a session remembers, so that reads within {@link #REUSE} need not ask the Domain
 * again: the lock of one session's checks, whether a check passed recently for the same person, and recording one.
 */
public final class SignInCheckSession {
    static final String CHECKED = "lookaheadSignInChecked";
    static final Duration REUSE = Duration.ofSeconds(60);
    record Checked(String person, Instant at) implements Serializable {}
    private final Clock clock;

    public SignInCheckSession(Clock clock) { this.clock = clock; }

    /** The lock of one session's checks; a request without a session checks on its own. */
    public static Object mutex(HttpSession session) {
        if (session == null) return new Object();
        try {
            return WebUtils.getSessionMutex(session);
        } catch (IllegalStateException ended) {
            return session;
        }
    }

    /** Whether this session passed a check for this person within {@link #REUSE}; null when the session has ended. */
    public Boolean passedRecently(HttpSession session, String person) {
        try {
            return session.getAttribute(CHECKED) instanceof Checked checked && checked.person().equals(person)
                    && clock.instant().isBefore(checked.at().plus(REUSE));
        } catch (IllegalStateException ended) {
            return null;
        }
    }

    /** Records the passed check on the session; false when the session ended meanwhile. */
    public boolean remember(HttpSession session, String person) {
        try {
            session.setAttribute(CHECKED, new Checked(person, clock.instant()));
            return true;
        } catch (IllegalStateException ended) {
            return false;
        }
    }
}
