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
        // The 5-minute directory re-check is gone: an admission granted hours ago still passes until the window ends.
        var req = request("/", now.minusSeconds(8*3600-1)); var chain = new MockFilterChain();
        filter().doFilter(req, new MockHttpServletResponse(), chain); assertNotNull(chain.getRequest());
        assertEquals(new DevAdmission.State("tester", "subject", now.minusSeconds(8*3600-1)), req.getSession().getAttribute(DevAdmission.ATTRIBUTE));
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
    @Test void staticProxyRejectsReservedAndAmbiguousTargets() {
        for(String path:new String[]{"//evil", "/bff/private", "/content/private", "/%2e%2e", "/x/../y", "/dev/access", "/.git/config", "/key.pem"})
            assertFalse(DevWebProxy.safePath(path),path);
        assertTrue(DevWebProxy.safePath("/learn")); assertTrue(DevWebProxy.safePath("/main-abcdef123.js"));
    }

    /** DLV-969: before admission, only our sign-in and sign-up pages, their bundles and the auth routes behind them pass. */
    @Test void ourSignInPagesTheirBundlesAndTheAuthRoutesPassBeforeAdmissionAndNothingElse() throws Exception {
        for (String path : new String[]{"/sign-in", "/sign-up", "/sign-in/forgot", "/sign-in/reset", "/sign-in/new-password", "/sign-in/code",
                "/sign-up/confirm", "/favicon.svg", "/favicon.ico", "/main-AB12cd_-.js", "/chunk-3NPQ_-3i.js", "/styles-ZX81QW2E.css",
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
                {"GET", "/bff/api/v1/auth/me"}, {"GET", "/main-ABCDEFGH.js.map"}, {"GET", "/main-ABC.js"}, {"GET", "/evil/main-ABCDEFGH.js"},
                {"POST", "/sign-in"}, {"POST", "/main-ABCDEFGH.js"}, {"GET", "/bff/api/v1/auth/password/sign-in"}, {"POST", "/bff/api/v1/auth/password/other"}}) {
            var req = request(attempt[1], null); req.setMethod(attempt[0]);
            var chain = new MockFilterChain(); filter().doFilter(req, new MockHttpServletResponse(), chain);
            assertNull(chain.getRequest(), attempt[0] + " " + attempt[1]);
        }
    }
}
