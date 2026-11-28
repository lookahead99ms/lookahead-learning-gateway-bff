package com.lookahead.gateway.security.session;

import static org.junit.jupiter.api.Assertions.*;

import java.time.*;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;

class DevAccessSessionTest {
  final Instant now = Instant.parse("2026-10-14T12:00:00Z");

  MockHttpServletRequest request(String path, Instant admitted) {
    var r = new MockHttpServletRequest("GET", path);
    if (admitted != null)
      r.getSession()
          .setAttribute(
              DevAccessSession.ATTRIBUTE,
              new DevAccessSession.State("tester", "subject", admitted));
    return r;
  }

  @Test
  void grantRotatesTheSessionIdKeepsTheSignedInStateAndSetsTheWindow() {
    var req = new MockHttpServletRequest("GET", "/login/oauth2/code/lookahead");
    var session = (MockHttpSession) req.getSession();
    session.setAttribute("SPRING_SECURITY_CONTEXT", "learner");
    session.setAttribute("learningReturnTo", "/learn");
    String before = session.getId();
    DevAccessSession.grant(
        req, "author@lookahead.dev", "010b25a0-c0f1-709c-467f-06e036639814", now);
    assertSame(session, req.getSession(false));
    assertNotEquals(before, session.getId());
    assertFalse(session.isInvalid());
    assertEquals(
        new DevAccessSession.State(
            "author@lookahead.dev", "010b25a0-c0f1-709c-467f-06e036639814", now),
        session.getAttribute(DevAccessSession.ATTRIBUTE));
    assertEquals("learner", session.getAttribute("SPRING_SECURITY_CONTEXT"));
    assertEquals("/learn", session.getAttribute("learningReturnTo"));
    assertEquals(8 * 3600, session.getMaxInactiveInterval());
    var fresh = new MockHttpServletRequest("GET", "/login/oauth2/code/lookahead");
    DevAccessSession.grant(fresh, "tester", "subject", now);
    assertNotNull(fresh.getSession(false));
    assertEquals(8 * 3600, fresh.getSession().getMaxInactiveInterval());
  }

  @Test
  void learnerLogoutKeepsOnlyAdmissionAndRotatesSession() {
    var req = request("/", now);
    var old = req.getSession();
    old.setAttribute("learnerToken", "secret");
    DevAccessSession.clearLearner(req);
    assertNotSame(old, req.getSession());
    assertNotNull(req.getSession().getAttribute(DevAccessSession.ATTRIBUTE));
    assertNull(req.getSession().getAttribute("learnerToken"));
    assertEquals(8 * 3600, req.getSession().getMaxInactiveInterval());
    var unadmitted = new MockHttpServletRequest("GET", "/");
    unadmitted.getSession().setAttribute("learnerToken", "secret");
    DevAccessSession.clearLearner(unadmitted);
    assertNull(unadmitted.getSession(false));
    DevAccessSession.clearLearner(new MockHttpServletRequest("GET", "/"));
  }
}
