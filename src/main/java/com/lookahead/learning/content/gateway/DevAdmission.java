package com.lookahead.learning.content.gateway;

import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.time.*;
import java.util.*;
import org.springframework.web.filter.OncePerRequestFilter;

/** Separate DEV admission; never grants learner authentication or application roles. */
public final class DevAdmission extends OncePerRequestFilter {
    static final String ATTRIBUTE = "lookaheadDevAdmission";
    static final Duration WINDOW = Duration.ofHours(8);
    /** The gate page and its helpers, plus the learner sign-in that now opens the gate (DLV-969). */
    static final Set<String> OPEN = Set.of("/dev/access", "/dev/csrf", "/dev/leave", "/dev/leave/complete",
        "/bff/login", "/oauth2/authorization/lookahead", "/login/oauth2/code/lookahead",
        // DLV-969: our own sign-in and sign-up, before anyone is admitted: the options and CSRF reads and the password routes.
        "/api/v1/auth/options", "/bff/api/v1/auth/csrf");
    /** DLV-969: the password routes behind those pages (POST only). */
    static final Set<String> OPEN_POSTS = Set.of("/bff/api/v1/auth/password/sign-in", "/bff/api/v1/auth/password/challenge",
        "/bff/api/v1/auth/password/sign-up", "/bff/api/v1/auth/password/sign-up/confirm", "/bff/api/v1/auth/password/sign-up/resend",
        "/bff/api/v1/auth/password/password/forgot", "/bff/api/v1/auth/password/password/reset");
    /** DLV-969: the Web pages of our sign-in and sign-up, readable (GET/HEAD only) before admission. */
    static final Set<String> OPEN_PAGES = Set.of("/sign-in", "/sign-up", "/sign-in/forgot", "/sign-in/reset", "/sign-in/new-password",
        "/sign-in/code", "/sign-up/confirm", "/favicon.svg", "/favicon.ico",
        // DLV-969: where a waiting account lands (header, waiting notice, the Essence section, footer); its code ships in
        // the hashed bundles below and it loads no other file.
        "/welcome");
    /** The Web build's top-level hashed bundles those pages load; lesson assets under /assets and /content stay closed. */
    static final java.util.regex.Pattern OPEN_BUNDLES = java.util.regex.Pattern.compile("/(main|chunk|polyfills|styles|worker)-[A-Za-z0-9_-]{6,16}\\.(js|css)");
    static boolean open(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (OPEN.contains(path)) return true;
        if ("POST".equals(request.getMethod()) && OPEN_POSTS.contains(path)) return true;
        boolean read = "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
        return read && (OPEN_PAGES.contains(path) || OPEN_BUNDLES.matcher(path).matches());
    }
    record State(String username, String subject, Instant admittedAt) {}
    private final Clock clock;
    DevAdmission(Clock clock) { this.clock = clock; }
    /** Records the gate admission on the signed-in session: the id rotates, the learner state stays, the window is absolute. */
    static void grant(HttpServletRequest request, String username, String subject, Instant now) {
        if (request.getSession(false) != null) request.changeSessionId();
        var session = request.getSession(true); session.setMaxInactiveInterval((int) WINDOW.toSeconds());
        session.setAttribute(ATTRIBUTE, new State(username, subject, now));
    }
    static void clearLearner(HttpServletRequest request) {
        restore(request, current(request));
    }
    /** The gate admission on this session, or null. */
    static Object current(HttpServletRequest request) {
        var session = request.getSession(false);
        return session == null ? null : session.getAttribute(ATTRIBUTE);
    }
    /** Ends the session and the learner sign-in; carries {@code admission} (a {@link State}, or null for none) into a fresh session. */
    static void restore(HttpServletRequest request, Object admission) {
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        if (admission instanceof State) {
            var replacement = request.getSession(true); replacement.setAttribute(ATTRIBUTE, admission);
            replacement.setMaxInactiveInterval((int) WINDOW.toSeconds());
        }
    }
    /** True while {@code admission} is a gate admission inside its absolute window. */
    static boolean open(Object admission, Instant now) {
        return admission instanceof State state && now.isBefore(state.admittedAt().plus(WINDOW));
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String path = request.getRequestURI();
        if (request.getLocalPort() == 8081 && Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1").contains(request.getRemoteAddr())
                && (path.startsWith("/actuator/health") || path.equals("/actuator/info"))) { chain.doFilter(request, response); return; }
        if (open(request)) { chain.doFilter(request, response); return; }
        var session = request.getSession(false);
        if (session != null && session.getAttribute(ATTRIBUTE) instanceof State state && clock.instant().isBefore(state.admittedAt().plus(WINDOW))) {
            chain.doFilter(request, response); return;
        }
        if (session != null) { SecurityAuditFilter.record(SecurityAuditFilter.Event.SESSION_ENDED); session.invalidate(); org.springframework.security.core.context.SecurityContextHolder.clearContext(); }
        response.setHeader("Cache-Control", "no-store");
        // /dev/session is polled by the Web shell as an API; the open /dev routes above never reach here.
        if (path.startsWith("/api/") || path.startsWith("/bff/") || path.startsWith("/content/") || path.startsWith("/dev/") || !"GET".equals(request.getMethod())) {
            response.setStatus(401); response.setContentType("application/json");
            response.getWriter().write("{\"code\":\"DEV_ADMISSION_REQUIRED\"}");
        } else response.sendRedirect("/dev/access");
    }
}
