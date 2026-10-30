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
    record State(String username, String subject, Instant admittedAt, Instant checkedAt) {}
    @FunctionalInterface interface Directory { boolean enabled(String username, String subject); }
    private final Directory directory;
    private final Clock clock;
    DevAdmission(Directory directory, Clock clock) { this.directory = directory; this.clock = clock; }
    static void clearLearner(HttpServletRequest request) {
        var session = request.getSession(false);
        Object admission = session == null ? null : session.getAttribute(ATTRIBUTE);
        if (session != null) session.invalidate();
        org.springframework.security.core.context.SecurityContextHolder.clearContext();
        if (admission instanceof State) {
            var replacement = request.getSession(true); replacement.setAttribute(ATTRIBUTE, admission);
            replacement.setMaxInactiveInterval(8 * 3600);
        }
    }
    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String path = request.getRequestURI();
        if (request.getLocalPort() == 8081 && Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1").contains(request.getRemoteAddr())
                && (path.startsWith("/actuator/health") || path.equals("/actuator/info"))) { chain.doFilter(request, response); return; }
        if (Set.of("/dev/access", "/dev/csrf", "/dev/leave", "/dev/leave/complete", "/dev/oauth2/authorization/admission", "/dev/login/oauth2/code/admission").contains(path)) {
            chain.doFilter(request, response); return;
        }
        var session = request.getSession(false);
        boolean admitted = false; boolean unavailable = false;
        if (session != null) synchronized (session) {
            if (session.getAttribute(ATTRIBUTE) instanceof State state && clock.instant().isBefore(state.admittedAt().plus(Duration.ofHours(8)))) {
                if (clock.instant().isBefore(state.checkedAt().plus(Duration.ofMinutes(5)))) admitted = true;
                else try {
                    admitted = directory.enabled(state.username(), state.subject());
                    if (admitted) session.setAttribute(ATTRIBUTE, new State(state.username(), state.subject(), state.admittedAt(), clock.instant()));
                } catch (RuntimeException failure) { unavailable = true; SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_UNAVAILABLE); }
            }
        }
        if (admitted) { chain.doFilter(request, response); return; }
        if (!unavailable && session != null) { SecurityAuditFilter.record(SecurityAuditFilter.Event.SESSION_ENDED); session.invalidate(); org.springframework.security.core.context.SecurityContextHolder.clearContext(); }
        response.setHeader("Cache-Control", "no-store");
        // /dev/session is polled by the Web shell as an API; the bypassed /dev routes above never reach here.
        if (unavailable || path.startsWith("/api/") || path.startsWith("/bff/") || path.startsWith("/content/") || path.startsWith("/dev/") || !"GET".equals(request.getMethod())) {
            response.setStatus(unavailable ? 503 : 401); response.setContentType("application/json");
            response.getWriter().write(unavailable ? "{\"code\":\"DEV_ADMISSION_UNAVAILABLE\"}" : "{\"code\":\"DEV_ADMISSION_REQUIRED\"}");
        } else response.sendRedirect("/dev/access");
    }
}
