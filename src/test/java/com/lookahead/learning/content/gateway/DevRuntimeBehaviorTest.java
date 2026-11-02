package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.*;
import org.springframework.mock.web.*;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.client.RestClient;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.http.MediaType;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class DevRuntimeBehaviorTest {
    final Instant now=Instant.parse("2026-10-14T12:00:00Z");
    OAuth2AuthenticationToken auth(){return new OAuth2AuthenticationToken(new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")),Map.of("sub","learner"),"sub"),List.of(new SimpleGrantedAuthority("ROLE_USER")),"lookahead");}
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void idleExpiryRemovesLearnerButKeepsAdmission() throws Exception {
        var request=new MockHttpServletRequest("GET","/learn");
        request.getSession().setAttribute(DevAdmission.ATTRIBUTE,new DevAdmission.State("tester","admission",now.minusSeconds(2000)));
        request.getSession().setAttribute(LearnerIdleFilter.LAST_ACTIVITY,now.minusSeconds(1800));
        SecurityContextHolder.getContext().setAuthentication(auth());
        var old=(MockHttpSession)request.getSession();
        new LearnerIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
        assertTrue(old.isInvalid()); assertNull(SecurityContextHolder.getContext().getAuthentication());
        assertNotNull(request.getSession().getAttribute(DevAdmission.ATTRIBUTE));
    }
    @Test void pollingDoesNotExtendLearnerActivity() throws Exception {
        for(String path:List.of("/bff/api/v1/auth/me","/dev/session","/dev/csrf","/actuator/health")){
            var request=new MockHttpServletRequest("GET",path);var previous=now.minusSeconds(100);
            request.getSession().setAttribute(LearnerIdleFilter.LAST_ACTIVITY,previous);SecurityContextHolder.getContext().setAuthentication(auth());
            new LearnerIdleFilter(Clock.fixed(now,ZoneOffset.UTC)).doFilter(request,new MockHttpServletResponse(),new MockFilterChain());
            assertEquals(previous,request.getSession().getAttribute(LearnerIdleFilter.LAST_ACTIVITY),path);
        }
        assertTrue(LearnerIdleFilter.activity(new MockHttpServletRequest("POST","/bff/api/v1/plans")));
        assertTrue(LearnerIdleFilter.activity(new MockHttpServletRequest("GET","/content/lesson.json")));
        assertFalse(LearnerIdleFilter.activity(new MockHttpServletRequest("GET","/main.js")));
    }
    MockEnvironment environment(){return new MockEnvironment().withProperty("app.oauth.frontend","https://dev.example.com")
        .withProperty("app.cognito.managed-login","https://learner.auth.us-east-2.amazoncognito.com")
        .withProperty("app.oauth.client-id","learner-client");}
    @Test void leaveClearsBothSessionsEvenIfUpstreamSignOutFails() {
        var learner=mock(GatewayController.class);var controller=new DevAccessController(environment(),learner);
        var request=new MockHttpServletRequest("POST","/dev/leave");var response=new MockHttpServletResponse();
        var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth());
        var old=(MockHttpSession)request.getSession();old.setAttribute("SPRING_SECURITY_CONTEXT",context);
        old.setAttribute(DevAdmission.ATTRIBUTE,new DevAdmission.State("tester","admission",now));
        when(learner.logout(any(),any(),any())).thenThrow(new IllegalStateException("synthetic upstream unavailable"));
        var result=controller.leave(request,response);
        verify(learner).logout(request,response,context.getAuthentication());
        assertTrue(old.isInvalid());assertNull(request.getSession(false));
        assertEquals("false",result.getBody().get("learnerSignOutConfirmed"));
        assertTrue(result.getBody().get("logoutUrl").contains("learner.auth.us-east-2.amazoncognito.com/logout"));
        assertTrue(result.getBody().get("logoutUrl").contains("%2Fdev%2Fleave%2Fcomplete"));
    }
    @Test void leaveCompletionReturnsToTheGateWithoutASecondProvider() throws Exception {
        // DLV-969: the learner provider is the gate's provider, so nothing is left to log out of after /dev/leave.
        var controller=new DevAccessController(environment(),mock(GatewayController.class));var response=new MockHttpServletResponse();
        controller.complete(response);assertEquals("/dev/access",response.getRedirectedUrl());assertEquals("no-store",response.getHeader("Cache-Control"));
        assertEquals("no-store",controller.access(null,null).getHeaders().getCacheControl());
        assertFalse(controller.access(null,null).getBody().contains("<script"));
    }
    @Test void accessPageIsSelfContainedAndItsPolicyHashesTheServedStyleBlock() throws Exception {
        var reply=new DevAccessController(environment(),mock(GatewayController.class)).access(null,null);
        String body=reply.getBody(),policy=reply.getHeaders().getFirst("Content-Security-Policy");
        // The page keeps its purpose and the admission link, and makes no network request of any kind.
        assertTrue(body.startsWith("<!doctype html>"));assertTrue(body.contains("<html lang=\"en\">"));assertTrue(body.contains("<meta name=\"viewport\""));
        assertTrue(body.contains("Authorized users"));assertTrue(body.contains("href=\"/bff/login?provider=password&amp;returnTo=%2F\""));
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
        String expected=Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(css.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(DevAccessPage.BASE_POLICY+"; style-src 'sha256-"+expected+"'",policy);
        assertEquals(1,policy.split("style-src",-1).length-1);
        // A page without exactly one style block, or a missing resource, fails at startup rather than serving a page the policy would block.
        assertThrows(IllegalStateException.class,()->DevAccessPage.styleHash("<html><body>no style</body></html>"));
        assertThrows(IllegalStateException.class,()->DevAccessPage.styleHash("<style>a</style><style>b</style>"));
        assertThrows(IllegalStateException.class,()->DevAccessPage.load("dev-access-missing.html"));
    }
    /** DLV-969: the gate page is our sign-in page; Google appears only while the switch is on. */
    @Test void accessPageOffersGoogleOnlyWhenSwitchedOn() {
        var on=new DevAccessController(environment().withProperty("app.cognito.google-sign-in","true"),mock(GatewayController.class)).access(null,null);
        String body=on.getBody();
        assertTrue(body.contains("href=\"/bff/login?provider=google&amp;returnTo=%2F\""));assertTrue(body.contains("Continue with Google"));
        assertTrue(body.indexOf("Continue with Google")<body.indexOf("Sign in with email and password"));
        assertTrue(body.contains("<svg viewBox=\"0 0 48 48\" aria-hidden=\"true\""));assertFalse(body.contains("<!--"));
        // The style block, and so the policy hash, is the same with or without Google.
        var off=new DevAccessController(environment(),mock(GatewayController.class)).access(null,null);
        assertEquals(off.getHeaders().getFirst("Content-Security-Policy"),on.getHeaders().getFirst("Content-Security-Policy"));
    }
    @Test void accessPageShowsOnlyFixedNotices() {
        var controller=new DevAccessController(environment(),mock(GatewayController.class));
        String pending=controller.access("pending",null).getBody();
        assertTrue(pending.contains("<p class=\"notice\" role=\"status\">Your sign-in worked. The owner has to approve your access before DEV opens."));
        String failed=controller.access(null,"<b>anything</b>").getBody();
        assertTrue(failed.contains("That sign-in did not complete. Try again."));assertFalse(failed.contains("<b>anything"));
        assertFalse(controller.access("other",null).getBody().contains("class=\"notice\""));
        assertEquals(DevAccessPage.Notice.PENDING,DevAccessPage.Notice.from("pending","signin"));
        assertThrows(IllegalStateException.class,()->new DevAccessPage("<style>a</style><p>no marks</p>").render(false,DevAccessPage.Notice.NONE));
        assertThrows(IllegalStateException.class,()->new DevAccessPage("<style>a</style><!--notice--><!--/google--><!--google-->").render(true,DevAccessPage.Notice.NONE));
    }
    MockEnvironment upstreams(){return new MockEnvironment().withProperty("app.oauth.domain-api-upstream","https://domain.lookahead-dev.internal:8443")
        .withProperty("app.gateway.web-upstream","https://web.lookahead-dev.internal:8443");}
    @Test void webProxyForwardsNoBrowserCredentialsOrQueries() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
            .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("Cookie"))
            .andRespond(withSuccess("<html>shell</html>",MediaType.TEXT_HTML));
        var request=new MockHttpServletRequest("GET","/learn");request.setQueryString("token=private");request.addHeader("Authorization","Bearer private");request.addHeader("Cookie","session=private");
        var result=new DevWebProxy(builder.build(),upstreams()).get(request);assertEquals(200,result.getStatusCode().value());assertEquals("no-store",result.getHeaders().getCacheControl());server.verify();
    }
    @Test void webProxyRefusesRedirectAndReservedRoutes() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn")).andRespond(withStatus(org.springframework.http.HttpStatus.FOUND).header("Location","https://elsewhere.example"));
        var proxy=new DevWebProxy(builder.build(),upstreams());assertEquals(502,proxy.get(new MockHttpServletRequest("GET","/learn")).getStatusCode().value());
        assertEquals(404,proxy.get(new MockHttpServletRequest("GET","/content/private")).getStatusCode().value());server.verify();
    }
    @Test void webProxyRefusesAnyWebUpstreamOtherThanTheStableName() {
        for(String rejected:List.of("https://web.attacker.test:8443","https://web.lookahead-dev.internal:8081","http://web.lookahead-dev.internal:8443"))
            assertThrows(IllegalStateException.class,()->new DevWebProxy(RestClient.builder().build(),upstreams().withProperty("app.gateway.web-upstream",rejected)),rejected);
        assertThrows(IllegalStateException.class,()->new DevWebProxy(RestClient.builder().build(),new MockEnvironment()));
    }
    @Test void unavailableStatusNeverInventsADeadline() {
        var client=mock(software.amazon.awssdk.services.dynamodb.DynamoDbClient.class);
        doThrow(new IllegalStateException()).when(client).getItem(any(java.util.function.Consumer.class));
        var controller=new DevSessionStatus(client,"state");assertEquals(503,controller.status().getStatusCode().value());controller.close();verify(client).close();
    }
    org.springframework.security.oauth2.core.oidc.user.OidcUser signedIn(Map<String,Object> claims){
        var all=new HashMap<String,Object>(Map.of("sub","010b25a0-c0f1-709c-467f-06e036639814"));all.putAll(claims);
        var token=new org.springframework.security.oauth2.core.oidc.OidcIdToken("synthetic-id-token",now.minusSeconds(5),now.plusSeconds(3600),all);
        return new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),token);
    }
    @Test void gateOpensOnAFreshLookAheadSignInWithUsernameOrSubject() {
        // DLV-969: no directory call; the ID token's auth_time must be at most 120 s old and at most 30 s ahead.
        var gate=DevGate.freshSignIn(Clock.fixed(now,ZoneOffset.UTC));
        var request=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");request.getSession().setAttribute("SPRING_SECURITY_CONTEXT","learner");
        gate.admit(request,signedIn(Map.of("cognito:username","author@lookahead.dev","auth_time",now.minusSeconds(120))));
        assertEquals(new DevAdmission.State("author@lookahead.dev","010b25a0-c0f1-709c-467f-06e036639814",now),request.getSession().getAttribute(DevAdmission.ATTRIBUTE));
        assertEquals("learner",request.getSession().getAttribute("SPRING_SECURITY_CONTEXT"));assertEquals(8*3600,request.getSession().getMaxInactiveInterval());
        var federated=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");
        gate.admit(federated,signedIn(Map.of("auth_time",now.plusSeconds(30))));
        assertEquals(new DevAdmission.State("010b25a0-c0f1-709c-467f-06e036639814","010b25a0-c0f1-709c-467f-06e036639814",now),federated.getSession().getAttribute(DevAdmission.ATTRIBUTE));
    }
    @Test void gateRefusesAStaleFutureOrMissingAuthTime() {
        var gate=DevGate.freshSignIn(Clock.fixed(now,ZoneOffset.UTC));
        for(Map<String,Object> claims:List.<Map<String,Object>>of(Map.of("auth_time",now.minusSeconds(121)),Map.of("auth_time",now.plusSeconds(31)),Map.of())){
            var request=new MockHttpServletRequest("GET","/login/oauth2/code/lookahead");
            assertThrows(IllegalStateException.class,()->gate.admit(request,signedIn(claims)),claims.toString());
            assertNull(request.getSession(false),claims.toString());
        }
    }
    @Test void gateConfigurationIsDevOnlyAndRegistersTheFilterAheadOfSecurity() {
        var config=new DevAdmissionConfiguration();
        assertThrows(IllegalStateException.class,()->config.devGate(new MockEnvironment().withProperty("app.deployment-environment","prod")));
        assertNotNull(config.devGate(new MockEnvironment().withProperty("app.deployment-environment","dev")));
        var registration=config.admissionFilter();assertEquals(-110,registration.getOrder());assertInstanceOf(DevAdmission.class,registration.getFilter());
    }
    @Test void statusShowsWarningAndMaintenanceWithoutPrivateOperationId() {
        var client=mock(software.amazon.awssdk.services.dynamodb.DynamoDbClient.class);
        var value=software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(Instant.now().plusSeconds(60).toString()).build();
        doReturn(software.amazon.awssdk.services.dynamodb.model.GetItemResponse.builder().item(Map.of("deadline",value,"operation",value)).build())
            .when(client).getItem(any(java.util.function.Consumer.class));
        var result=new DevSessionStatus(client,"state").status();
        assertEquals(true,result.getBody().get("warning"));assertEquals(true,result.getBody().get("maintenance"));assertFalse(result.getBody().containsKey("operation"));
    }
}
