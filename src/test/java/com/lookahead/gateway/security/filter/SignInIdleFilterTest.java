package com.lookahead.gateway.security.filter;

import com.lookahead.gateway.log.OpsLogTest;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInSession;
import com.lookahead.gateway.security.session.TestSessionState;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.time.*;
import java.util.*;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import static org.junit.jupiter.api.Assertions.*;

/** The idle filter of the DEV profile: 30 minutes without activity end the sign-in or the test session; the gate admission stays. */
class SignInIdleFilterTest {
    @Nested class IdleExpiry {
    final Instant now=Instant.parse("2026-10-14T12:00:00Z");
    OAuth2AuthenticationToken auth(){return new OAuth2AuthenticationToken(new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),Map.of("sub","learner"),"sub"),List.of(new SimpleGrantedAuthority("ROLE_USER")),"lookahead");}
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void idleExpiryRemovesLearnerButKeepsAdmission() throws Exception {
        var request=new MockHttpServletRequest("GET","/learn");
        request.getSession().setAttribute(DevAccessSession.ATTRIBUTE,new DevAccessSession.State("tester","admission",now.minusSeconds(2000)));
        request.getSession().setAttribute(SignInSession.LAST_ACTIVITY,now.minusSeconds(1800));
        SecurityContextHolder.getContext().setAuthentication(auth());
        var old=(MockHttpSession)request.getSession();
        new SignInIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
        assertTrue(old.isInvalid()); assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(request.getSession().getAttribute(DevAccessSession.ATTRIBUTE));
    }
    /** DLV-971 (owner, 2026-11-06): a test session idles out like a sign-in, and takes the staff sign-in kept aside with it. */
    @Test void idleExpiryEndsATestSessionAndTheStaffSignInKeptAsideButKeepsAdmission() throws Exception {
        var request=new MockHttpServletRequest("GET","/learn");
        request.getSession().setAttribute(DevAccessSession.ATTRIBUTE,new DevAccessSession.State("tester","admission",now.minusSeconds(2000)));
        request.getSession().setAttribute(SignInSession.LAST_ACTIVITY,now.minusSeconds(1800));
        request.getSession().setAttribute(TestSessionState.STAFF_SIGN_IN,auth());
        SecurityContextHolder.getContext().setAuthentication(new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
        var old=(MockHttpSession)request.getSession();
        var capture=new ListAppender<ILoggingEvent>();capture.start();
        var logger=(Logger)LoggerFactory.getLogger("lookahead.event");logger.addAppender(capture);
        try { new SignInIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain()); }
        finally { logger.detachAppender(capture); }
        assertTrue(old.isInvalid()); assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(request.getSession().getAttribute(DevAccessSession.ATTRIBUTE));
        assertNull(request.getSession().getAttribute(TestSessionState.STAFF_SIGN_IN));
        assertEquals("Signed out: IDLE_TIMEOUT (no activity for 30 minutes); the test session ended with the staff sign-in kept aside, the DEV gate stays open",capture.list.get(0).getFormattedMessage());
    }
    /** DLV-971: a test session's requests refresh the stamp, so Back to my account does not meet an idle sign-out. */
    @Test void aTestSessionRequestRefreshesTheActivityStamp() throws Exception {
        var request=new MockHttpServletRequest("POST","/bff/api/v1/plans");var previous=now.minusSeconds(100);
        request.getSession().setAttribute(SignInSession.LAST_ACTIVITY,previous);
        SecurityContextHolder.getContext().setAuthentication(new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
        new SignInIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
        assertEquals(now,request.getSession().getAttribute(SignInSession.LAST_ACTIVITY));
        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }
    @Test void pollingDoesNotExtendLearnerActivity() throws Exception {
        for(String path:List.of("/bff/api/v1/auth/me","/dev/session","/dev/csrf","/actuator/health")){
            var request=new MockHttpServletRequest("GET",path);var previous=now.minusSeconds(100);
            request.getSession().setAttribute(SignInSession.LAST_ACTIVITY,previous);SecurityContextHolder.getContext().setAuthentication(auth());
            new SignInIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
            assertEquals(previous,request.getSession().getAttribute(SignInSession.LAST_ACTIVITY),path);
        }
        assertTrue(SignInIdleFilter.activity(new MockHttpServletRequest("POST","/bff/api/v1/plans")));
        assertTrue(SignInIdleFilter.activity(new MockHttpServletRequest("GET","/content/lesson.json")));
        assertFalse(SignInIdleFilter.activity(new MockHttpServletRequest("GET","/main.js")));
    }
    }

    @Nested class IdleSignOutLine {
    final Instant now = Instant.parse("2026-10-14T12:00:00Z");
    MockHttpServletRequest request(String path, Instant admitted) {
        var r = new MockHttpServletRequest("GET", path);
        if (admitted != null) r.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("tester", "subject", admitted));
        return r;
    }
    /** DLV-969: 30 idle minutes end the learner sign-in, and the line says so. */
    @Test void anIdleSignInEndsWithALogLine() throws Exception {
        var events = (Logger) LoggerFactory.getLogger("lookahead.event");
        var capture = new ListAppender<ILoggingEvent>(); capture.start(); events.addAppender(capture);
        try {
            for (Object last : new Object[]{now.minusSeconds(1800), null}) {
                var req = request("/learn", now); req.getSession().setAttribute(SignInSession.LAST_ACTIVITY, last);
                var context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new OAuth2AuthenticationToken(user(now), List.of(), "lookahead"));
                SecurityContextHolder.setContext(context);
                new SignInIdleFilter(Clock.fixed(now, ZoneOffset.UTC)).doFilter(req, new MockHttpServletResponse(), new MockFilterChain());
            }
        } finally { events.detachAppender(capture); SecurityContextHolder.clearContext(); }
        assertEquals("Signed out: IDLE_TIMEOUT (no activity for 30 minutes); the learner sign-in ended, the DEV gate stays open", capture.list.get(0).getFormattedMessage());
        assertTrue(OpsLogTest.pairs(capture.list.get(0)).contains("reason=IDLE_TIMEOUT"));
        assertTrue(OpsLogTest.pairs(capture.list.get(1)).contains("reason=NO_ACTIVITY_RECORDED"));
    }
    OidcUser user(Instant authTime) {
        var claims = new HashMap<String, Object>(Map.of("sub", "subject", "cognito:username", "person@example.invalid"));
        if (authTime != null) claims.put("auth_time", authTime);
        var token = new OidcIdToken("synthetic-id-token", now.minusSeconds(5), now.plusSeconds(300), claims);
        return new DefaultOidcUser(List.of(), token, "sub");
    }

    }
}
