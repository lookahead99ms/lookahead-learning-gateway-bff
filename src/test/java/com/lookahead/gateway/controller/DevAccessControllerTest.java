package com.lookahead.gateway.controller;

import com.lookahead.gateway.security.handler.DevAccessHandler;
import com.lookahead.gateway.security.handler.DevAccessPage;
import com.lookahead.gateway.security.handler.SignOutHandler;
import com.lookahead.gateway.security.oauth.SignInProvider;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.TestSessionState;
import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import org.mockito.ArgumentCaptor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.method.annotation.CsrfTokenArgumentResolver;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.WebUtils;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * The DEV gate's own routes, driven through the controller's route methods over the real DevAccessHandler: the access page,
 * leaving DEV and its completion. The handler on its own is in DevAccessHandlerTest; the sign-out behind the leave route in SignOutHandlerTest.
 */
class DevAccessControllerTest {
    final Instant now=Instant.parse("2026-10-14T12:00:00Z");
    OAuth2AuthenticationToken auth(){return new OAuth2AuthenticationToken(new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),Map.of("sub","learner"),"sub"),List.of(new SimpleGrantedAuthority("ROLE_USER")),"lookahead");}
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    MockEnvironment environment(){return new MockEnvironment().withProperty("app.oauth.frontend","https://dev.example.com")
        .withProperty("app.cognito.managed-login","https://learner.auth.us-east-2.amazoncognito.com")
        .withProperty("app.oauth.client-id","learner-client");}
    /** DLV-1015: the real sign-out handler (leaving DEV lives there now) with no collaborators; its {@code logout} is stubbed in each test, as the controller mock's was. */
    SignOutHandler signOut(){return spy(new SignOutHandler(null,null,null,null,null,null,environment()));}
    /** DLV-1015: the route bodies are in DevAccessHandler; the controller is built over it as the configuration builds it (the Google switch read from the environment, once). */
    static DevAccessController controller(MockEnvironment environment,SignOutHandler signOut){return new DevAccessController(new DevAccessHandler(SignInProvider.googleEnabled(environment),signOut));}
    @Test void leaveClearsBothSessionsEvenIfUpstreamSignOutFails() {
        var learner=signOut();var controller=controller(environment(),learner);
        var request=new MockHttpServletRequest("POST","/dev/leave");var response=new MockHttpServletResponse();
        var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth());
        var old=(MockHttpSession)request.getSession();old.setAttribute("SPRING_SECURITY_CONTEXT",context);
        old.setAttribute(DevAccessSession.ATTRIBUTE,new DevAccessSession.State("tester","admission",now));
        doThrow(new IllegalStateException("synthetic upstream unavailable")).when(learner).logout(any(),any(),any());
        var result=controller.leave(request,response);
        verify(learner).logout(request,response,context.getAuthentication());
        assertTrue(old.isInvalid());assertNull(request.getSession(false));
        assertEquals("false",result.getBody().get("learnerSignOutConfirmed"));
        assertTrue(result.getBody().get("logoutUrl").contains("learner.auth.us-east-2.amazoncognito.com/logout"));
        assertTrue(result.getBody().get("logoutUrl").contains("%2Fdev%2Fleave%2Fcomplete"));
    }
    /** DLV-969 (2026-11-04): Exit DEV from a test account also ends the staff sign-in kept aside behind it. */
    @Test void leaveFromATestAccountSignsOutTheStaffSignInKeptAside() {
        var learner=signOut();doReturn(null).when(learner).logout(any(),any(),any());var controller=controller(environment(),learner);
        var request=new MockHttpServletRequest("POST","/dev/leave");var response=new MockHttpServletResponse();
        var staff=auth();var session=(MockHttpSession)request.getSession();
        session.setAttribute(TestSessionState.STAFF_SIGN_IN,staff);
        var context=SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
        session.setAttribute("SPRING_SECURITY_CONTEXT",context);
        var result=controller.leave(request,response);
        verify(learner).logout(request,response,staff);
        assertTrue(session.isInvalid());assertEquals("true",result.getBody().get("learnerSignOutConfirmed"));
        // Signed out entirely (no sign-in, no test account): nothing to sign out of.
        var nobody=signOut();
        controller(environment(),nobody).leave(new MockHttpServletRequest("POST","/dev/leave"),new MockHttpServletResponse());
        // The handler is asked to leave and for the address, and signs nobody out (its collaborators are null: any use would fail the request).
        verify(nobody).leaveDev(any(),any());verify(nobody).leaveDevUrl();verify(nobody,never()).logout(any(),any(),any());verifyNoMoreInteractions(nobody);
    }
    @Test void leaveCompletionReturnsToTheGateWithoutASecondProvider() throws Exception {
        // DLV-969: the learner provider is the gate's provider, so nothing is left to log out of after /dev/leave.
        var controller=controller(environment(),mock(SignOutHandler.class));var response=new MockHttpServletResponse();
        controller.complete(response);assertEquals("/dev/access",response.getRedirectedUrl());assertEquals("no-store",response.getHeader("Cache-Control"));
        assertEquals("no-store",controller.access(null,null).getHeaders().getCacheControl());
        assertFalse(controller.access(null,null).getBody().contains("<script"));
    }
    @Test void accessPageIsSelfContainedAndItsPolicyHashesTheServedStyleBlock() throws Exception {
        var reply=controller(environment(),mock(SignOutHandler.class)).access(null,null);
        String body=reply.getBody(),policy=reply.getHeaders().getFirst("Content-Security-Policy");
        // The page keeps its purpose and the admission link, and makes no network request of any kind.
        assertTrue(body.startsWith("<!doctype html>"));assertTrue(body.contains("<html lang=\"en\">"));assertTrue(body.contains("<meta name=\"viewport\""));
        assertTrue(body.contains("Authorized users"));assertTrue(body.contains("href=\"/sign-in?returnTo=%2F\""));
        assertTrue(body.contains("Sign in with email and password"));
        assertTrue(body.contains("One sign-in both opens DEV and signs you in to your account."));assertFalse(body.contains("/dev/oauth2/"));
        assertTrue(body.contains("aria-describedby=\"signin-hint\""));assertTrue(body.contains("id=\"signin-hint\""));
        // Google is off until the pool has the provider; the served page carries no template marks and no notice.
        assertFalse(body.contains("Continue with Google"));assertFalse(body.contains("provider=google"));assertFalse(body.contains("<!--"));
        assertFalse(body.contains("class=\"notice\""));
        assertFalse(body.contains("<script"));assertFalse(body.contains("http://"));assertFalse(body.contains("https://"));
        assertFalse(body.contains("<link"));assertFalse(body.contains("<img"));assertFalse(body.contains("@import"));assertFalse(body.contains("url("));
        assertFalse(body.contains(" style=\""));assertEquals(body.indexOf("<style"),body.lastIndexOf("<style"));
        // The policy stays strict and admits exactly the served inline style block by its own hash.
        assertTrue(policy.startsWith("default-src 'none'; base-uri 'none'; frame-ancestors 'none'; style-src 'sha256-"));assertTrue(policy.endsWith("'"));
        String css=body.substring(body.indexOf("<style>")+"<style>".length(),body.indexOf("</style>"));
        String expected=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(css.getBytes(StandardCharsets.UTF_8)));
        assertEquals(DevAccessPage.BASE_POLICY+"; style-src 'sha256-"+expected+"'",policy);
        assertEquals(1,policy.split("style-src",-1).length-1);
        // A page without exactly one style block, or a missing resource, fails at startup rather than serving a page the policy would block.
        assertThrows(IllegalStateException.class,()->DevAccessPage.styleHash("<html><body>no style</body></html>"));
        assertThrows(IllegalStateException.class,()->DevAccessPage.styleHash("<style>a</style><style>b</style>"));
        assertThrows(IllegalStateException.class,()->DevAccessPage.load("dev-access-missing.html"));
    }
    /** DLV-969: the gate page is our sign-in page; Google appears only while the switch is on. */
    @Test void accessPageOffersGoogleOnlyWhenSwitchedOn() {
        var on=controller(environment().withProperty("app.cognito.google-sign-in","true"),mock(SignOutHandler.class)).access(null,null);
        String body=on.getBody();
        assertTrue(body.contains("href=\"/bff/login?provider=google&amp;returnTo=%2F\""));assertTrue(body.contains("Continue with Google"));
        assertTrue(body.indexOf("Continue with Google")<body.indexOf("Sign in with email and password"));
        assertTrue(body.contains("<svg viewBox=\"0 0 48 48\" aria-hidden=\"true\""));assertFalse(body.contains("<!--"));
        // The style block, and so the policy hash, is the same with or without Google.
        var off=controller(environment(),mock(SignOutHandler.class)).access(null,null);
        assertEquals(off.getHeaders().getFirst("Content-Security-Policy"),on.getHeaders().getFirst("Content-Security-Policy"));
    }
    @Test void accessPageShowsOnlyFixedNotices() {
        var controller=controller(environment(),mock(SignOutHandler.class));
        String pending=controller.access("pending",null).getBody();
        assertTrue(pending.contains("<p class=\"notice\" role=\"status\">Your sign-in worked. The owner has to approve your access before DEV opens."));
        String failed=controller.access(null,"<b>anything</b>").getBody();
        assertTrue(failed.contains("That sign-in did not complete. Try again."));assertFalse(failed.contains("<b>anything"));
        assertFalse(controller.access("other",null).getBody().contains("class=\"notice\""));
        assertEquals(DevAccessPage.Notice.PENDING,DevAccessPage.Notice.from("pending","signin"));
        assertThrows(IllegalStateException.class,()->new DevAccessPage("<style>a</style><p>no marks</p>").render(false,DevAccessPage.Notice.NONE));
        assertThrows(IllegalStateException.class,()->new DevAccessPage("<style>a</style><!--notice--><!--/google--><!--google-->").render(true,DevAccessPage.Notice.NONE));
    }
    /** DLV-1015: each route, reached through Spring MVC, is one call to its handler method, and the handler's answer goes back unchanged. */
    @Test void eachRouteIsOneCallToItsHandlerMethod() throws Exception {
        var handler=mock(DevAccessHandler.class);
        var mvc=MockMvcBuilders.standaloneSetup(new DevAccessController(handler))
            .setCustomArgumentResolvers(new CsrfTokenArgumentResolver()).build();
        doReturn(ResponseEntity.status(291).header("X-From","the handler").body("<p>the handler's page</p>")).when(handler).access(any(),any());
        var page=mvc.perform(MockMvcRequestBuilders.get("/dev/access").queryParam("access","pending").queryParam("error","signin")).andReturn().getResponse();
        assertEquals(291,page.getStatus());assertEquals("the handler","" + page.getHeader("X-From"));assertEquals("<p>the handler's page</p>",page.getContentAsString());
        assertTrue(page.getContentType().startsWith("text/html"));
        verify(handler).access("pending","signin");
        mvc.perform(MockMvcRequestBuilders.get("/dev/access")).andReturn();
        verify(handler).access(null,null);verifyNoMoreInteractions(handler);
        var token=new DefaultCsrfToken("X-CSRF-TOKEN","_csrf","synthetic-token");
        doReturn(ResponseEntity.status(292).body(Map.of("from","the handler"))).when(handler).csrf(any());
        var csrf=mvc.perform(MockMvcRequestBuilders.get("/dev/csrf")
            .requestAttr(CsrfToken.class.getName(),token)).andReturn().getResponse();
        assertEquals(292,csrf.getStatus());assertEquals("{\"from\":\"the handler\"}",csrf.getContentAsString());
        verify(handler).csrf(token);verifyNoMoreInteractions(handler);
        doReturn(ResponseEntity.status(293).body(Map.of("from","the handler"))).when(handler).leave(any(),any());
        var left=mvc.perform(MockMvcRequestBuilders.post("/dev/leave")).andReturn();
        assertEquals(293,left.getResponse().getStatus());assertEquals("{\"from\":\"the handler\"}",left.getResponse().getContentAsString());
        var request=ArgumentCaptor.forClass(HttpServletRequest.class);var response=ArgumentCaptor.forClass(HttpServletResponse.class);
        verify(handler).leave(request.capture(),response.capture());verifyNoMoreInteractions(handler);
        assertEquals("/dev/leave",request.getValue().getRequestURI());
        assertSame(left.getResponse(),WebUtils.getNativeResponse(response.getValue(),MockHttpServletResponse.class));
        var completed=mvc.perform(MockMvcRequestBuilders.get("/dev/leave/complete")).andReturn();
        verify(handler).complete(response.capture());verifyNoMoreInteractions(handler);
        assertSame(completed.getResponse(),WebUtils.getNativeResponse(response.getValue(),MockHttpServletResponse.class));
        // Only these methods and paths.
        assertEquals(405,mvc.perform(MockMvcRequestBuilders.get("/dev/leave")).andReturn().getResponse().getStatus());
        assertEquals(405,mvc.perform(MockMvcRequestBuilders.post("/dev/access")).andReturn().getResponse().getStatus());
        assertEquals(404,mvc.perform(MockMvcRequestBuilders.get("/dev/other")).andReturn().getResponse().getStatus());
        verifyNoMoreInteractions(handler);
    }
    /** DLV-969: the gate card's waiting notice still renders as a fallback after waiting accounts moved to /welcome. */
    @Test void gateCardStillShowsTheWaitingNoticeAsAFallback() {
        String pending=controller(environment(),mock(SignOutHandler.class)).access("pending",null).getBody();
        assertTrue(pending.contains("The owner has to approve your access before DEV opens."));
    }
}
