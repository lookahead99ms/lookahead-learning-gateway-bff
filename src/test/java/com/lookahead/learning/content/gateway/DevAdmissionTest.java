package com.lookahead.learning.content.gateway;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import java.time.*;
import static org.junit.jupiter.api.Assertions.*;

class DevAdmissionTest {
    final Instant now = Instant.parse("2026-10-14T12:00:00Z");
    MockHttpServletRequest request(String path, Instant admitted, Instant checked) {
        var r = new MockHttpServletRequest("GET", path);
        if (admitted != null) r.getSession().setAttribute(DevAdmission.ATTRIBUTE, new DevAdmission.State("tester", "subject", admitted, checked));
        return r;
    }
    @Test void shellRequiresAdmissionAndApiNeverGetsLoginHtml() throws Exception {
        var filter = new DevAdmission((u,s) -> true, Clock.fixed(now, ZoneOffset.UTC));
        var shell = new MockHttpServletResponse(); filter.doFilter(request("/",null,null),shell,new MockFilterChain());
        assertEquals("/dev/access", shell.getRedirectedUrl());
        var api = new MockHttpServletResponse(); filter.doFilter(request("/bff/api/v1/plans",null,null),api,new MockFilterChain());
        assertEquals(401,api.getStatus()); assertTrue(api.getContentAsString().contains("DEV_ADMISSION_REQUIRED"));
    }
    @Test void localManagementPortServesHealthAndReleaseInfoWithoutAdmissionButNothingElse() throws Exception {
        var filter = new DevAdmission((u,s) -> true, Clock.fixed(now, ZoneOffset.UTC));
        for (String path : new String[]{"/actuator/health/readiness", "/actuator/info"}) {
            var req = request(path, null, null); req.setLocalPort(8081); req.setRemoteAddr("127.0.0.1");
            var chain = new MockFilterChain(); filter.doFilter(req, new MockHttpServletResponse(), chain);
            assertNotNull(chain.getRequest(), path);
        }
        for (String[] attempt : new String[][]{{"/actuator/info", "8080", "127.0.0.1"}, {"/actuator/info", "8081", "10.0.0.9"}, {"/actuator/env", "8081", "127.0.0.1"}}) {
            var req = request(attempt[0], null, null); req.setLocalPort(Integer.parseInt(attempt[1])); req.setRemoteAddr(attempt[2]);
            var chain = new MockFilterChain(); var response = new MockHttpServletResponse(); filter.doFilter(req, response, chain);
            assertNull(chain.getRequest(), String.join(" ", attempt)); assertEquals("/dev/access", response.getRedirectedUrl());
        }
    }
    @Test void disabledTesterClearsBothStates() throws Exception {
        var req = request("/", now.minusSeconds(600), now.minusSeconds(300)); var old = (MockHttpSession)req.getSession();
        old.setAttribute("SPRING_SECURITY_CONTEXT", "learner");
        new DevAdmission((u,s) -> false,Clock.fixed(now,ZoneOffset.UTC)).doFilter(req,new MockHttpServletResponse(),new MockFilterChain());
        assertTrue(old.isInvalid());
    }
    @Test void directoryOutageFailsClosedAfterFreshnessAndCanRecover() throws Exception {
        var req=request("/bff/api/v1/plans",now.minusSeconds(600),now.minusSeconds(300)); var response=new MockHttpServletResponse();
        new DevAdmission((u,s)->{throw new IllegalStateException();},Clock.fixed(now,ZoneOffset.UTC)).doFilter(req,response,new MockFilterChain());
        assertEquals(503,response.getStatus()); assertNotNull(req.getSession(false));
    }
    @Test void absoluteExpiryCannotSlide() throws Exception {
        var req=request("/",now.minusSeconds(8*3600),now); var old=(MockHttpSession)req.getSession();
        new DevAdmission((u,s)->true,Clock.fixed(now,ZoneOffset.UTC)).doFilter(req,new MockHttpServletResponse(),new MockFilterChain());
        assertTrue(old.isInvalid());
    }
    @Test void learnerLogoutKeepsOnlyAdmissionAndRotatesSession() {
        var req=request("/",now,now); var old=req.getSession(); old.setAttribute("learnerToken","secret");
        DevAdmission.clearLearner(req); assertNotSame(old,req.getSession()); assertNotNull(req.getSession().getAttribute(DevAdmission.ATTRIBUTE));
        assertNull(req.getSession().getAttribute("learnerToken"));
    }
    @Test void staticProxyRejectsReservedAndAmbiguousTargets() {
        for(String path:new String[]{"//evil", "/bff/private", "/content/private", "/%2e%2e", "/x/../y", "/dev/access", "/.git/config", "/key.pem"})
            assertFalse(DevWebProxy.safePath(path),path);
        assertTrue(DevWebProxy.safePath("/learn")); assertTrue(DevWebProxy.safePath("/main-abcdef123.js"));
    }
}
