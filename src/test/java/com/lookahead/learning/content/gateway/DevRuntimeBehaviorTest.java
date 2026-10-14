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
        request.getSession().setAttribute(DevAdmission.ATTRIBUTE,new DevAdmission.State("tester","admission",now.minusSeconds(2000),now));
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
        .withProperty("app.oauth.client-id","learner-client")
        .withProperty("app.admission.managed-login","https://admission.auth.us-east-2.amazoncognito.com")
        .withProperty("app.admission.client-id","admission-client");}
    @Test void leaveClearsBothSessionsEvenIfUpstreamSignOutFails() {
        var learner=mock(GatewayController.class);var controller=new DevAccessController(environment(),learner);
        var request=new MockHttpServletRequest("POST","/dev/leave");var response=new MockHttpServletResponse();
        var context=SecurityContextHolder.createEmptyContext();context.setAuthentication(auth());
        var old=(MockHttpSession)request.getSession();old.setAttribute("SPRING_SECURITY_CONTEXT",context);
        old.setAttribute(DevAdmission.ATTRIBUTE,new DevAdmission.State("tester","admission",now,now));
        when(learner.logout(any(),any(),any())).thenThrow(new IllegalStateException("synthetic upstream unavailable"));
        var result=controller.leave(request,response);
        verify(learner).logout(request,response,context.getAuthentication());
        assertTrue(old.isInvalid());assertNull(request.getSession(false));
        assertEquals("false",result.getBody().get("learnerSignOutConfirmed"));
        assertTrue(result.getBody().get("logoutUrl").contains("learner.auth.us-east-2.amazoncognito.com/logout"));
        assertTrue(result.getBody().get("logoutUrl").contains("%2Fdev%2Fleave%2Fcomplete"));
    }
    @Test void admissionCompletionUsesSeparateProvider() throws Exception {
        var controller=new DevAccessController(environment(),mock(GatewayController.class));var response=new MockHttpServletResponse();
        controller.complete(response);assertTrue(response.getRedirectedUrl().startsWith("https://admission.auth.us-east-2.amazoncognito.com/logout?"));
        assertEquals("no-store",controller.access().getHeaders().getCacheControl());
        assertFalse(controller.access().getBody().contains("<script"));
    }
    @Test void webProxyForwardsNoBrowserCredentialsOrQueries() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web-blue.lookahead-dev.internal:8443/learn"))
            .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist("Cookie"))
            .andRespond(withSuccess("<html>shell</html>",MediaType.TEXT_HTML));
        var request=new MockHttpServletRequest("GET","/learn");request.setQueryString("token=private");request.addHeader("Authorization","Bearer private");request.addHeader("Cookie","session=private");
        var result=new DevWebProxy(builder.build(),"blue").get(request);assertEquals(200,result.getStatusCode().value());assertEquals("no-store",result.getHeaders().getCacheControl());server.verify();
    }
    @Test void webProxyRefusesRedirectAndReservedRoutes() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web-blue.lookahead-dev.internal:8443/learn")).andRespond(withStatus(org.springframework.http.HttpStatus.FOUND).header("Location","https://elsewhere.example"));
        var proxy=new DevWebProxy(builder.build(),"blue");assertEquals(502,proxy.get(new MockHttpServletRequest("GET","/learn")).getStatusCode().value());
        assertEquals(404,proxy.get(new MockHttpServletRequest("GET","/content/private")).getStatusCode().value());server.verify();
    }
    @Test void unavailableStatusNeverInventsADeadline() {
        var client=mock(software.amazon.awssdk.services.dynamodb.DynamoDbClient.class);
        doThrow(new IllegalStateException()).when(client).getItem(any(java.util.function.Consumer.class));
        var controller=new DevSessionStatus(client,"state");assertEquals(503,controller.status().getStatusCode().value());controller.close();verify(client).close();
    }
    @Test void directoryRequiresEnabledUserAndMatchingSubject() {
        var client=mock(software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient.class);
        var config=new DevAdmissionConfiguration();
        var directory=config.admissionDirectory(client,new MockEnvironment().withProperty("app.admission.pool-id","us-east-2_test"));
        var enabled=software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse.builder().enabled(true)
            .userAttributes(software.amazon.awssdk.services.cognitoidentityprovider.model.AttributeType.builder().name("sub").value("expected").build()).build();
        doReturn(enabled).when(client).adminGetUser(any(java.util.function.Consumer.class));
        assertTrue(directory.enabled("tester","expected"));assertFalse(directory.enabled("tester","other"));
        doReturn(enabled.toBuilder().enabled(false).build()).when(client).adminGetUser(any(java.util.function.Consumer.class));
        assertFalse(directory.enabled("tester","expected"));
        doThrow(software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException.builder().message("missing").build())
            .when(client).adminGetUser(any(java.util.function.Consumer.class));
        assertFalse(directory.enabled("tester","expected"));
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
