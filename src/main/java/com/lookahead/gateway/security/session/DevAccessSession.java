package com.lookahead.gateway.security.session;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.time.Instant;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * The DEV gate admission kept on the server session: where it is stored, how long it holds, and how
 * it is granted, read and carried over.
 */
public final class DevAccessSession {
  public static final String ATTRIBUTE = "lookaheadDevAdmission";
  public static final Duration WINDOW = Duration.ofHours(8);

  /**
   * DLV-969: how often an open gate session asks the sign-in pool whether its user may still be
   * here.
   */
  public static final Duration RECHECK = Duration.ofMinutes(5);

  private DevAccessSession() {}

  public record State(String username, String subject, Instant admittedAt) {}

  /**
   * Records the gate admission on the signed-in session: the id rotates, the learner state stays,
   * the window is absolute.
   */
  public static void grant(
      HttpServletRequest request, String username, String subject, Instant now) {
    if (request.getSession(false) != null) request.changeSessionId();
    var session = request.getSession(true);
    session.setMaxInactiveInterval((int) WINDOW.toSeconds());
    session.setAttribute(ATTRIBUTE, new State(username, subject, now));
  }

  public static void clearLearner(HttpServletRequest request) {
    restore(request, current(request));
  }

  /** The gate admission on this session, or null. */
  public static Object current(HttpServletRequest request) {
    var session = request.getSession(false);
    return session == null ? null : session.getAttribute(ATTRIBUTE);
  }

  /**
   * Ends the session and the learner sign-in; carries {@code admission} (a {@link State}, or null
   * for none) into a fresh session.
   */
  public static void restore(HttpServletRequest request, Object admission) {
    var session = request.getSession(false);
    if (session != null) session.invalidate();
    SecurityContextHolder.clearContext();
    if (admission instanceof State) {
      var replacement = request.getSession(true);
      replacement.setAttribute(ATTRIBUTE, admission);
      replacement.setMaxInactiveInterval((int) WINDOW.toSeconds());
    }
  }

  /** True while {@code admission} is a gate admission inside its absolute window. */
  public static boolean open(Object admission, Instant now) {
    return admission instanceof State state && now.isBefore(state.admittedAt().plus(WINDOW));
  }
}
