package com.lookahead.gateway.security.filter;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.proxy.DevWebProxy;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInSession;
import com.lookahead.gateway.security.session.TestSessionState;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

public final class SignInIdleFilter extends OncePerRequestFilter {
  static final Duration IDLE = Duration.ofMinutes(30);
  private final Clock clock;

  public SignInIdleFilter(Clock clock) {
    this.clock = clock;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    var session = request.getSession(false);
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    // DLV-971 (owner, 2026-11-06): a test session idles out like a sign-in, and its requests
    // refresh the stamp, so the staff sign-in kept aside behind it is not signed out on the first
    // request after Back to my account.
    boolean testSession = TestSessionState.active(authentication);
    if (session != null && (authentication instanceof OAuth2AuthenticationToken || testSession)) {
      Instant now = clock.instant();
      Object last = session.getAttribute(SignInSession.LAST_ACTIVITY);
      if (!(last instanceof Instant instant) || !now.isBefore(instant.plus(IDLE))) {
        // DLV-969: the learner sign-in ends after 30 idle minutes; the DEV gate admission stays.
        boolean idle = last instanceof Instant;
        String ended =
            testSession
                ? "the test session ended with the staff sign-in kept aside"
                : "the learner sign-in ended";
        OpsLog.refused("sign-in.idle-timeout", idle ? "IDLE_TIMEOUT" : "NO_ACTIVITY_RECORDED")
            .log(
                idle
                    ? "Signed out: IDLE_TIMEOUT (no activity for {} minutes); {}, the DEV gate"
                        + " stays open"
                    : "Signed out: NO_ACTIVITY_RECORDED (the session had no activity time; the"
                        + " limit is {} idle minutes); {}, the DEV gate stays open",
                IDLE.toMinutes(),
                ended);
        DevAccessSession.clearLearner(request);
      } else if (activity(request)) session.setAttribute(SignInSession.LAST_ACTIVITY, now);
    }
    chain.doFilter(request, response);
  }

  public static boolean activity(HttpServletRequest r) {
    String path = r.getRequestURI();
    if (path.equals("/bff/api/v1/auth/me")
        || path.endsWith("/csrf")
        || path.startsWith("/dev/")
        || path.startsWith("/actuator/")) return false;
    return !r.getMethod().equals("GET") && !r.getMethod().equals("HEAD")
        || path.startsWith("/content/")
        || DevWebProxy.safePath(path) && !path.contains(".");
  }
}
