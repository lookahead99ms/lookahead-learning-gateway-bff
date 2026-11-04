package com.lookahead.learning.content.gateway;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;

class DevAdmissionTest {
    final Instant now = Instant.parse("2026-10-14T12:00:00Z");
    DevAdmission filter() { return new DevAdmission(Clock.fixed(now, ZoneOffset.UTC)); }
    MockHttpServletRequest request(String path, Instant admitted) {
        var r = new MockHttpServletRequest("GET", path);
        if (admitted != null) r.getSession().setAttribute(DevAdmission.ATTRIBUTE, new DevAdmission.State("tester", "subject", admitted));
        return r;
    }
    @Test void shellRequiresAdmissionAndApiNeverGetsLoginHtml() throws Exception {
        var shell = new MockHttpServletResponse(); filter().doFilter(request("/",null),shell,new MockFilterChain());
        assertEquals("/dev/access", shell.getRedirectedUrl());
        var api = new MockHttpServletResponse(); filter().doFilter(request("/bff/api/v1/plans",null),api,new MockFilterChain());
        assertEquals(401,api.getStatus()); assertTrue(api.getContentAsString().contains("DEV_ADMISSION_REQUIRED"));
        var post = new MockHttpServletResponse(); var mutation = request("/learn", null); mutation.setMethod("POST");
        filter().doFilter(mutation, post, new MockFilterChain()); assertEquals(401, post.getStatus()); assertNull(post.getRedirectedUrl());
    }
    @Test void localManagementPortServesHealthAndReleaseInfoWithoutAdmissionButNothingElse() throws Exception {
        for (String path : new String[]{"/actuator/health/readiness", "/actuator/info"}) {
            var req = request(path, null); req.setLocalPort(8081); req.setRemoteAddr("127.0.0.1");
            var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
            assertNotNull(chain.getRequest(), path);
        }
        for (String[] attempt : new String[][]{{"/actuator/info", "8080", "127.0.0.1"}, {"/actuator/info", "8081", "10.0.0.9"}, {"/actuator/env", "8081", "127.0.0.1"}}) {
            var req = request(attempt[0], null); req.setLocalPort(Integer.parseInt(attempt[1])); req.setRemoteAddr(attempt[2]);
            var chain = new MockFilterChain(); var response = new MockHttpServletResponse(); filter().doFilter(req, response, chain);
            assertNull(chain.getRequest(), String.join(" ", attempt)); assertEquals("/dev/access", response.getRedirectedUrl());
        }
    }
    @Test void gatePageHelpersAndTheLearnerSignInPassWithoutAdmission() throws Exception {
        // DLV-969: the gate button starts the ordinary learner sign-in, so its three routes must reach Spring Security unadmitted.
        for (String path : new String[]{"/dev/access", "/dev/csrf", "/dev/leave", "/dev/leave/complete", "/bff/login", "/oauth2/authorization/lookahead", "/login/oauth2/code/lookahead"}) {
            var req = request(path, null); req.getSession().setAttribute("learningReturnTo", "/learn");
            var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
            assertNotNull(chain.getRequest(), path); assertEquals("/learn", req.getSession().getAttribute("learningReturnTo"), path);
        }
        for (String path : new String[]{"/dev/oauth2/authorization/admission", "/dev/login/oauth2/code/admission", "/oauth2/authorization/other", "/login/oauth2/code/other", "/bff/logout/complete"}) {
            var chain = new MockFilterChain(); var response = new MockHttpServletResponse(); filter().doFilter(request(path, null), response, chain);
            assertNull(chain.getRequest(), path); assertNotEquals(200, response.getStatus(), path);
        }
    }
    @Test void statusRouteAnswersJsonNotLoginHtmlWithoutAdmission() throws Exception {
        // The Web shell polls /dev/session as an API; before or after admission it must never receive login HTML.
        var anonymous = new MockHttpServletResponse(); filter().doFilter(request("/dev/session",null),anonymous,new MockFilterChain());
        assertEquals(401,anonymous.getStatus()); assertNull(anonymous.getRedirectedUrl());
        assertEquals("application/json",anonymous.getContentType()); assertTrue(anonymous.getContentAsString().contains("DEV_ADMISSION_REQUIRED"));
        assertEquals("no-store",anonymous.getHeader("Cache-Control"));
        var expired = request("/dev/session", now.minusSeconds(8*3600)); var old=(MockHttpSession)expired.getSession();
        var afterExpiry = new MockHttpServletResponse(); filter().doFilter(expired, afterExpiry, new MockFilterChain());
        assertEquals(401, afterExpiry.getStatus()); assertNull(afterExpiry.getRedirectedUrl()); assertTrue(old.isInvalid());
        var admitted = request("/dev/session", now.minusSeconds(60)); var chain = new MockFilterChain();
        filter().doFilter(admitted, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest());
    }
    @Test void admissionNeedsNoDirectoryAndHoldsForTheWholeWindow() throws Exception {
        // No directory: while the pool still knows the user, an admission granted hours ago passes until the window ends.
        var req = request("/", now.minusSeconds(8*3600-1)); var chain = new MockFilterChain();
        filter().doFilter(req, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest());
        assertEquals(new DevAdmission.State("tester", "subject", now.minusSeconds(8*3600-1)), req.getSession().getAttribute(DevAdmission.ATTRIBUTE));
    }
    /** DLV-969: every five minutes an open session asks the pool; a disabled or deleted user loses the gate. */
    @Test void aUserTheOwnerDisabledOrDeletedLosesTheGateWithinFiveMinutes() throws Exception {
        var asked = new java.util.ArrayList<String>();
        var allowed = new java.util.concurrent.atomic.AtomicBoolean(true);
        var filter = new DevAdmission(Clock.fixed(now, ZoneOffset.UTC), username -> { asked.add(username); return allowed.get(); });
        // Admitted four minutes ago: not asked yet.
        var fresh = request("/", now.minusSeconds(240)); var chain = new MockFilterChain();
        filter.doFilter(fresh, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest()); assertTrue(asked.isEmpty());
        // Admitted six minutes ago: asked once, then not again for five minutes.
        var due = request("/", now.minusSeconds(360)); var session = (MockHttpSession) due.getSession();
        filter.doFilter(due, new MockHttpServletResponse(), new MockFilterChain());
        assertEquals(java.util.List.of("tester"), asked); assertEquals(now, session.getAttribute(DevAdmission.CHECKED));
        var again = new MockHttpServletRequest("GET", "/learn"); again.setSession(session); chain = new MockFilterChain();
        filter.doFilter(again, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest()); assertEquals(1, asked.size());
        // Checked six minutes ago and now disabled or deleted: the session ends and the browser goes back to the gate.
        session.setAttribute(DevAdmission.CHECKED, now.minusSeconds(360)); allowed.set(false);
        var page = new MockHttpServletRequest("GET", "/learn"); page.setSession(session); var response = new MockHttpServletResponse();
        filter.doFilter(page, response, new MockFilterChain());
        assertTrue(session.isInvalid()); assertEquals("/dev/access", response.getRedirectedUrl());
        var api = request("/bff/api/v1/plans", now.minusSeconds(600)); var apiResponse = new MockHttpServletResponse();
        filter.doFilter(api, apiResponse, new MockFilterChain()); assertEquals(401, apiResponse.getStatus());
    }
    @Test void whenThePoolDoesNotAnswerTheSessionContinuesAndTheNextRequestAsksAgain() throws Exception {
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var filter = new DevAdmission(Clock.fixed(now, ZoneOffset.UTC), username -> { calls.incrementAndGet(); throw new IllegalStateException("pool down"); });
        var req = request("/", now.minusSeconds(600)); var session = (MockHttpSession) req.getSession(); var chain = new MockFilterChain();
        filter.doFilter(req, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest()); assertNull(session.getAttribute(DevAdmission.CHECKED));
        var next = new MockHttpServletRequest("GET", "/learn"); next.setSession(session);
        filter.doFilter(next, new MockHttpServletResponse(), new MockFilterChain()); assertEquals(2, calls.get()); assertFalse(session.isInvalid());
    }
    @Test void absoluteExpiryCannotSlide() throws Exception {
        var req=request("/",now.minusSeconds(8*3600)); var old=(MockHttpSession)req.getSession(); old.setAttribute("SPRING_SECURITY_CONTEXT", "learner");
        var response=new MockHttpServletResponse(); filter().doFilter(req,response,new MockFilterChain());
        assertTrue(old.isInvalid()); assertEquals("/dev/access", response.getRedirectedUrl()); assertNull(req.getSession(false));
    }
    @Test void grantRotatesTheSessionIdKeepsTheSignedInStateAndSetsTheWindow() {
        var req = new MockHttpServletRequest("GET", "/login/oauth2/code/lookahead"); var session = (MockHttpSession) req.getSession();
        session.setAttribute("SPRING_SECURITY_CONTEXT", "learner"); session.setAttribute("learningReturnTo", "/learn"); String before = session.getId();
        DevAdmission.grant(req, "author@lookahead.dev", "010b25a0-c0f1-709c-467f-06e036639814", now);
        assertSame(session, req.getSession(false)); assertNotEquals(before, session.getId()); assertFalse(session.isInvalid());
        assertEquals(new DevAdmission.State("author@lookahead.dev", "010b25a0-c0f1-709c-467f-06e036639814", now), session.getAttribute(DevAdmission.ATTRIBUTE));
        assertEquals("learner", session.getAttribute("SPRING_SECURITY_CONTEXT")); assertEquals("/learn", session.getAttribute("learningReturnTo"));
        assertEquals(8*3600, session.getMaxInactiveInterval());
        var fresh = new MockHttpServletRequest("GET", "/login/oauth2/code/lookahead");
        DevAdmission.grant(fresh, "tester", "subject", now); assertNotNull(fresh.getSession(false)); assertEquals(8*3600, fresh.getSession().getMaxInactiveInterval());
    }
    @Test void learnerLogoutKeepsOnlyAdmissionAndRotatesSession() {
        var req=request("/",now); var old=req.getSession(); old.setAttribute("learnerToken","secret");
        DevAdmission.clearLearner(req); assertNotSame(old,req.getSession()); assertNotNull(req.getSession().getAttribute(DevAdmission.ATTRIBUTE));
        assertNull(req.getSession().getAttribute("learnerToken")); assertEquals(8*3600, req.getSession().getMaxInactiveInterval());
        var unadmitted = new MockHttpServletRequest("GET", "/"); unadmitted.getSession().setAttribute("learnerToken", "secret");
        DevAdmission.clearLearner(unadmitted); assertNull(unadmitted.getSession(false));
        DevAdmission.clearLearner(new MockHttpServletRequest("GET", "/"));
    }
    /** DLV-969 (owner, 2026-11-04): gate opened, refused, rechecked, closed and expired, each with a reason and never who. */
    @Test void everyGateDecisionIsLoggedWithItsReason() throws Exception {
        var events = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var capture = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>(); capture.start(); events.addAppender(capture);
        try {
            var gate = DevGate.freshSignIn(Clock.fixed(now, ZoneOffset.UTC));
            gate.admit(new MockHttpServletRequest("GET", "/login/oauth2/code/lookahead"), user(now.minusSeconds(30)));
            assertEquals("DEV gate opened for a fresh sign-in: open for 8 hours, rechecked every 5 minutes", capture.list.getLast().getFormattedMessage());
            assertEquals(ch.qos.logback.classic.Level.INFO, capture.list.getLast().getLevel());
            assertThrows(IllegalStateException.class, () -> gate.admit(new MockHttpServletRequest(), user(now.minusSeconds(600))));
            var stale = capture.list.getLast();
            assertEquals(ch.qos.logback.classic.Level.WARN, stale.getLevel());
            assertEquals("DEV gate refused: STALE_SIGN_IN (the gate opens only for a sign-in made in the last 120 s)", stale.getFormattedMessage());
            assertTrue(OpsLogTest.pairs(stale).containsAll(java.util.List.of("event.action=dev-gate.admitted", "event.outcome=refused", "reason=STALE_SIGN_IN", "signIn.ageSeconds=600")));
            assertThrows(IllegalStateException.class, () -> gate.admit(new MockHttpServletRequest(), user(now.plusSeconds(60))));
            assertTrue(OpsLogTest.pairs(capture.list.getLast()).contains("reason=SIGN_IN_TIME_AHEAD"));
            assertThrows(IllegalStateException.class, () -> gate.admit(new MockHttpServletRequest(), user(null)));
            assertTrue(OpsLogTest.pairs(capture.list.getLast()).contains("reason=MISSING_AUTH_TIME"));

            // Recheck passed, then the user is disabled, then the pool does not answer.
            var allowed = new java.util.concurrent.atomic.AtomicReference<Boolean>(true);
            var filter = new DevAdmission(Clock.fixed(now, ZoneOffset.UTC), username -> { if (allowed.get() == null) throw new IllegalStateException("down " + username); return allowed.get(); });
            filter.doFilter(request("/", now.minusSeconds(600)), new MockHttpServletResponse(), new MockFilterChain());
            assertEquals("DEV gate recheck passed: the user is still enabled in the sign-in pool", capture.list.getLast().getFormattedMessage());
            allowed.set(null);
            filter.doFilter(request("/", now.minusSeconds(600)), new MockHttpServletResponse(), new MockFilterChain());
            assertEquals("DEV gate recheck could not reach the sign-in pool (IllegalStateException); the session continues and the next request asks again",
                capture.list.getLast().getFormattedMessage());
            assertTrue(OpsLogTest.pairs(capture.list.getLast()).contains("reason=PROVIDER_UNAVAILABLE"));
            allowed.set(false);
            filter.doFilter(request("/", now.minusSeconds(600)), new MockHttpServletResponse(), new MockFilterChain());
            assertEquals("DEV gate closed: the 5-minute recheck found the user disabled or deleted in the sign-in pool; session ended", capture.list.getLast().getFormattedMessage());
            assertEquals(ch.qos.logback.classic.Level.WARN, capture.list.getLast().getLevel());
            // The 8-hour window ends; a browser with no admission is refused at INFO.
            filter().doFilter(request("/learn", now.minusSeconds(8 * 3600)), new MockHttpServletResponse(), new MockFilterChain());
            assertEquals("DEV gate closed: the 8-hour window ended; session ended", capture.list.getLast().getFormattedMessage());
            assertTrue(OpsLogTest.pairs(capture.list.getLast()).contains("reason=WINDOW_EXPIRED"));
            filter().doFilter(request("/learn", null), new MockHttpServletResponse(), new MockFilterChain());
            assertEquals("DEV gate closed for GET /learn: no admission in this browser session", capture.list.getLast().getFormattedMessage());
            assertEquals(ch.qos.logback.classic.Level.INFO, capture.list.getLast().getLevel());
        } finally { events.detachAppender(capture); }
        for (var line : capture.list) {
            assertFalse(line.getFormattedMessage().contains("tester") || line.getFormattedMessage().contains("person@example.invalid"), line.getFormattedMessage());
            assertTrue(OpsLogTest.pairs(line).stream().noneMatch(pair -> pair.contains("person@example.invalid") || pair.contains("subject")), line.getFormattedMessage());
        }
    }

    /** DLV-969: 30 idle minutes end the learner sign-in, and the line says so. */
    @Test void anIdleSignInEndsWithALogLine() throws Exception {
        var events = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var capture = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>(); capture.start(); events.addAppender(capture);
        try {
            for (Object last : new Object[]{now.minusSeconds(1800), null}) {
                var req = request("/learn", now); req.getSession().setAttribute(LearnerIdleFilter.LAST_ACTIVITY, last);
                var context = org.springframework.security.core.context.SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user(now), java.util.List.of(), "lookahead"));
                org.springframework.security.core.context.SecurityContextHolder.setContext(context);
                new LearnerIdleFilter(Clock.fixed(now, ZoneOffset.UTC)).doFilter(req, new MockHttpServletResponse(), new MockFilterChain());
            }
        } finally { events.detachAppender(capture); org.springframework.security.core.context.SecurityContextHolder.clearContext(); }
        assertEquals("Signed out after 30 idle minutes: the learner sign-in ended, the DEV gate stays open", capture.list.get(0).getFormattedMessage());
        assertTrue(OpsLogTest.pairs(capture.list.get(0)).contains("reason=IDLE_TIMEOUT"));
        assertTrue(OpsLogTest.pairs(capture.list.get(1)).contains("reason=NO_ACTIVITY_RECORDED"));
    }

    org.springframework.security.oauth2.core.oidc.user.OidcUser user(Instant authTime) {
        var claims = new java.util.HashMap<String, Object>(java.util.Map.of("sub", "subject", "cognito:username", "person@example.invalid"));
        if (authTime != null) claims.put("auth_time", authTime);
        var token = new org.springframework.security.oauth2.core.oidc.OidcIdToken("synthetic-id-token", now.minusSeconds(5), now.plusSeconds(300), claims);
        return new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(java.util.List.of(), token, "sub");
    }

    @Test void staticProxyRejectsReservedAndAmbiguousTargets() {
        for(String path:new String[]{"//evil", "/bff/private", "/content/private", "/%2e%2e", "/x/../y", "/dev/access", "/.git/config", "/key.pem"})
            assertFalse(DevWebProxy.safePath(path),path);
        assertTrue(DevWebProxy.safePath("/learn")); assertTrue(DevWebProxy.safePath("/main-abcdef123.js"));
    }

    /** DLV-969: before admission, only our sign-in and sign-up pages, their bundles and the auth routes behind them pass. */
    @Test void ourSignInPagesTheirBundlesAndTheAuthRoutesPassBeforeAdmissionAndNothingElse() throws Exception {
        for (String path : new String[]{"/sign-in", "/sign-up", "/sign-in/forgot", "/sign-in/reset", "/sign-in/new-password", "/sign-in/code",
                "/sign-up/confirm", "/welcome", "/favicon.svg", "/favicon.ico", "/main-AB12cd_-.js", "/chunk-3NPQ_-3i.js", "/styles-ZX81QW2E.css",
                "/polyfills-ABCDEFGH.js", "/worker-ABCDEFGH.js", "/api/v1/auth/options", "/bff/api/v1/auth/csrf"}) {
            for (String method : new String[]{"GET", "HEAD"}) {
                var req = request(path, null); req.setMethod(method);
                var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
                assertNotNull(chain.getRequest(), method + " " + path);
            }
        }
        for (String path : new String[]{"/bff/api/v1/auth/password/sign-in", "/bff/api/v1/auth/password/challenge", "/bff/api/v1/auth/password/sign-up",
                "/bff/api/v1/auth/password/sign-up/confirm", "/bff/api/v1/auth/password/sign-up/resend",
                "/bff/api/v1/auth/password/password/forgot", "/bff/api/v1/auth/password/password/reset"}) {
            var req = request(path, null); req.setMethod("POST");
            var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
            assertNotNull(chain.getRequest(), path);
        }
        // Still closed: other pages, lesson assets and content, other APIs, writes to the pages, source maps and look-alikes.
        for (String[] attempt : new String[][]{{"GET", "/learn"}, {"GET", "/"}, {"GET", "/sign-in/choose"}, {"GET", "/sign-in/../learn"},
                {"GET", "/assets/scenes/landing/a.svg"}, {"GET", "/assets/visual-code-presentation.js"}, {"GET", "/content/indexes/learn.json"},
                {"GET", "/bff/api/v1/auth/me"}, {"POST", "/welcome"}, {"GET", "/welcome/extra"}, {"GET", "/main-ABCDEFGH.js.map"}, {"GET", "/main-ABC.js"}, {"GET", "/evil/main-ABCDEFGH.js"},
                {"POST", "/sign-in"}, {"POST", "/main-ABCDEFGH.js"}, {"GET", "/bff/api/v1/auth/password/sign-in"}, {"POST", "/bff/api/v1/auth/password/other"}}) {
            var req = request(attempt[1], null); req.setMethod(attempt[0]);
            var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
            assertNull(chain.getRequest(), attempt[0] + " " + attempt[1]);
        }
    }
}
