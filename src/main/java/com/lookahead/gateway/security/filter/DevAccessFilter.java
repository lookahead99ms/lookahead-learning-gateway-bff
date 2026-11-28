package com.lookahead.gateway.security.filter;

import com.lookahead.gateway.client.DevAccessClient;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.session.DevAccessSession;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;
import org.slf4j.event.Level;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** Separate DEV admission; never grants learner authentication or application roles. */
public final class DevAccessFilter extends OncePerRequestFilter {
  /** The gate page and its helpers, plus the learner sign-in that now opens the gate (DLV-969). */
  static final Set<String> OPEN =
      Set.of(
          "/dev/access",
          "/dev/csrf",
          "/dev/leave",
          "/dev/leave/complete",
          "/bff/login",
          "/oauth2/authorization/lookahead",
          "/login/oauth2/code/lookahead",
          // DLV-969: our own sign-in and sign-up, before anyone is admitted: the options and CSRF
          // reads and the password routes.
          "/api/v1/auth/options",
          "/bff/api/v1/auth/csrf");

  /** DLV-969: the password routes behind those pages (POST only). */
  static final Set<String> OPEN_POSTS =
      Set.of(
          "/bff/api/v1/auth/password/sign-in",
          "/bff/api/v1/auth/password/challenge",
          "/bff/api/v1/auth/password/sign-up",
          "/bff/api/v1/auth/password/sign-up/confirm",
          "/bff/api/v1/auth/password/sign-up/resend",
          "/bff/api/v1/auth/password/password/forgot",
          "/bff/api/v1/auth/password/password/reset");

  /**
   * DLV-969: the Web pages of our sign-in and sign-up, readable (GET/HEAD only) before admission.
   */
  static final Set<String> OPEN_PAGES =
      Set.of(
          "/sign-in",
          "/sign-up",
          "/sign-in/forgot",
          "/sign-in/reset",
          "/sign-in/new-password",
          "/sign-in/code",
          "/sign-up/confirm",
          "/favicon.svg",
          "/favicon.ico",
          // DLV-969: where a waiting account lands (header, waiting notice, the Essence section,
          // footer); its code ships in the hashed bundles below and it loads no other file.
          "/welcome");

  /**
   * The Web build's top-level hashed bundles those pages load; lesson assets under /assets and
   * /content stay closed.
   */
  static final Pattern OPEN_BUNDLES =
      Pattern.compile("/(main|chunk|polyfills|styles|worker)-[A-Za-z0-9_-]{6,16}\\.(js|css)");

  static boolean open(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (OPEN.contains(path)) return true;
    if ("POST".equals(request.getMethod()) && OPEN_POSTS.contains(path)) return true;
    boolean read = "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
    return read && (OPEN_PAGES.contains(path) || OPEN_BUNDLES.matcher(path).matches());
  }

  /**
   * The session attribute holding when the sign-in pool last confirmed this session's user; until
   * the first answer the admission time counts. An open gate session is asked again every {@link
   * DevAccessSession#RECHECK}, the interval the session class holds beside the admission window.
   */
  static final String CHECKED = "lookaheadDevAdmissionChecked";

  private final Clock clock;

  /**
   * Asks the sign-in pool whether a user is still enabled; when the call throws, the session
   * continues until the next request asks again.
   */
  private final DevAccessClient account;

  public DevAccessFilter(Clock clock, DevAccessClient account) {
    this.clock = clock;
    this.account = account;
  }

  /**
   * At most every {@link DevAccessSession#RECHECK}: a disabled or deleted user loses the gate
   * within five minutes, not eight hours.
   */
  private boolean stillAllowed(HttpSession session, DevAccessSession.State state) {
    Instant now = clock.instant(),
        checked = session.getAttribute(CHECKED) instanceof Instant at ? at : state.admittedAt();
    if (now.isBefore(checked.plus(DevAccessSession.RECHECK))) return true;
    try {
      if (!account.allowed(state.username())) {
        OpsLog.refused("dev-gate.rechecked", "USER_DISABLED_OR_DELETED")
            .log(
                "DEV gate closed: USER_DISABLED_OR_DELETED (the {}-minute recheck found the user"
                    + " disabled or deleted in the sign-in pool); session ended",
                DevAccessSession.RECHECK.toMinutes());
        return false;
      }
      session.setAttribute(CHECKED, now);
      OpsLog.success("dev-gate.rechecked")
          .log("DEV gate recheck passed: the user is still enabled in the sign-in pool");
    } catch (RuntimeException unavailable) {
      // The pool did not answer: keep the session; the next request asks again.
      OpsLog.failed("dev-gate.rechecked", "PROVIDER_UNAVAILABLE")
          .addKeyValue("exception.types", OpsLog.types(unavailable))
          .log(
              "DEV gate recheck failed: PROVIDER_UNAVAILABLE (the sign-in pool did not answer: {});"
                  + " the session continues and the next request asks again",
              OpsLog.types(unavailable));
    }
    return true;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws IOException, ServletException {
    String path = request.getRequestURI();
    if (request.getLocalPort() == 8081
        && Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1").contains(request.getRemoteAddr())
        && (path.startsWith("/actuator/health") || path.equals("/actuator/info"))) {
      chain.doFilter(request, response);
      return;
    }
    if (open(request)) {
      chain.doFilter(request, response);
      return;
    }
    var session = request.getSession(false);
    if (session != null
        && session.getAttribute(DevAccessSession.ATTRIBUTE) instanceof DevAccessSession.State state
        && clock.instant().isBefore(state.admittedAt().plus(DevAccessSession.WINDOW))
        && stillAllowed(session, state)) {
      chain.doFilter(request, response);
      return;
    }
    if (session != null
        && session.getAttribute(DevAccessSession.ATTRIBUTE) instanceof DevAccessSession.State state
        && !clock.instant().isBefore(state.admittedAt().plus(DevAccessSession.WINDOW)))
      OpsLog.refused("dev-gate.expired", "WINDOW_EXPIRED")
          .log(
              "DEV gate closed: WINDOW_EXPIRED (the {}-hour window ended); session ended",
              DevAccessSession.WINDOW.toHours());
    // Not admitted yet (a first visit, a crawler, a signed-out browser): INFO, so the gate page
    // itself never floods WARN.
    else if (session == null
        || !(session.getAttribute(DevAccessSession.ATTRIBUTE) instanceof DevAccessSession.State))
      OpsLog.event(Level.INFO, "dev-gate.required", "refused")
          .addKeyValue("reason", "DEV_ADMISSION_REQUIRED")
          .addKeyValue("http.method", OpsLog.method(request))
          .addKeyValue("url.path", OpsLog.path(request))
          .log(
              "DEV gate closed for {} {}: DEV_ADMISSION_REQUIRED (no admission in this browser"
                  + " session)",
              OpsLog.method(request),
              OpsLog.path(request));
    if (session != null) {
      OpsLog.audit(OpsLog.AuditEvent.SESSION_ENDED);
      session.invalidate();
      SecurityContextHolder.clearContext();
    }
    response.setHeader("Cache-Control", "no-store");
    // /dev/session is polled by the Web shell as an API; the open /dev routes above never reach
    // here.
    if (path.startsWith("/api/")
        || path.startsWith("/bff/")
        || path.startsWith("/content/")
        || path.startsWith("/dev/")
        || !"GET".equals(request.getMethod())) {
      response.setStatus(401);
      response.setContentType("application/json");
      response.getWriter().write("{\"code\":\"DEV_ADMISSION_REQUIRED\"}");
    } else response.sendRedirect("/dev/access");
  }
}
