package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthPropertiesConfiguration;
import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.*;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * DLV-969 S35: staff use a DEV test account inside the open gate. Real cloud Spring security and controllers; the
 * Domain is a controlled server. The gate admission is put in the session as DevAdmission would after a sign-in.
 */
@SpringBootTest(classes=TestSessionIntegrationTest.Application.class, properties={
    "spring.config.name=cloud-security-test", "app.deployment-environment=dev",
    "app.oauth.frontend=https://learn.example.test", "app.oauth.domain-api-upstream=https://domain.example.test",
    "app.oauth.client-id=syntheticclient12345", "app.oauth.client-secret=synthetic-client-secret-never-used-outside-fixtures",
    "app.cognito.issuer=https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example",
    "app.cognito.managed-login=https://example.auth.us-east-2.amazoncognito.com",
    "app.cognito.scope-prefix=lookahead", "app.cognito.gateway-secret=synthetic-internal-secret-never-used-outside-fixtures"})
@ActiveProfiles("gateway")
class TestSessionIntegrationTest {
    static final String LEARNER = "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a";
    @Configuration @EnableAutoConfiguration
    @Import({GatewayConfiguration.class,GatewayClientConfiguration.class,OAuthPropertiesConfiguration.class,
        GatewayController.class,CloudAccountController.class,PasswordSignInController.class,IdentityProxyController.class,
        AccountProxyController.class,GatewayErrorHandler.class,TestSessionController.class,ControlledHttp.class})
    static class Application {}
    @Configuration static class ControlledHttp {
        MockRestServiceServer server;
        @Bean @Primary RestClient controlledHttp(){var builder=RestClient.builder();server=MockRestServiceServer.bindTo(builder).build();return builder.build();}
    }
    @Autowired WebApplicationContext context;
    @Autowired ControlledHttp fixture;
    @Autowired OAuthSettings settings;
    @Autowired ClientRegistrationRepository registrations;
    @Autowired org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository authorizedClients;
    MockMvc mvc;
    @BeforeEach void reset(){fixture.server.reset();mvc=MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();SecurityContextHolder.clearContext();}

    /** A browser whose DEV gate an admin opened, now signed out of the platform. */
    MockHttpSession gate(){
        var session=new MockHttpSession(context.getServletContext());
        session.setAttribute(DevAdmission.ATTRIBUTE,new DevAdmission.State("admin@example.test","sub-admin",Instant.now()));
        return session;
    }
    String csrf(MockHttpSession session)throws Exception{
        return new JsonMapper().readTree(mvc.perform(get("/api/v1/auth/csrf").session(session)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data").path("token").asString();
    }
    void domain(String path,HttpMethod method,String answer,org.springframework.http.HttpStatus status){
        fixture.server.expect(requestTo(settings.domainApiUpstream()+path)).andExpect(method(method))
            .andExpect(MockRestRequestMatchers.header(TestSessionController.SECRET_HEADER,settings.gatewaySecret())).andExpect(MockRestRequestMatchers.header(TestSessionController.HOLDER_HEADER,"sub-admin"))
            .andExpect(headerDoesNotExist("Authorization"))
            .andRespond(withStatus(status).contentType(MediaType.APPLICATION_JSON).body(answer));
    }
    /** LogicalSignInFilter asks the Domain about a signed-in person on every BFF call. */
    void signedInCheck(){
        fixture.server.expect(org.springframework.test.web.client.ExpectedCount.manyTimes(),requestTo(settings.domainApiUpstream()+"/api/v1/auth/me"))
            .andExpect(MockRestRequestMatchers.header("Authorization",org.hamcrest.Matchers.startsWith("Bearer "))).andRespond(withSuccess("{\"data\":{}}",MediaType.APPLICATION_JSON));
    }
    MockHttpSession started(MockHttpSession session)throws Exception{
        domain("/internal/v1/test-sessions/start",HttpMethod.POST,"{\"data\":{\"accountId\":\""+LEARNER+"\"}}",org.springframework.http.HttpStatus.OK);
        String before=session.getId();
        mvc.perform(post("/bff/api/v1/auth/test-session").session(session).header("X-CSRF-TOKEN",csrf(session))
                .contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isOk()).andExpect(jsonPath("data.next").value("/"));
        fixture.server.verify();fixture.server.reset();
        assertThat(session.getId()).isNotEqualTo(before);
        var signedIn=((SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        assertThat(TestSessionController.active(signedIn)).isTrue();assertThat(signedIn.getPrincipal()).isEqualTo(LEARNER);
        assertThat(session.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        return session;
    }

    @Test void aSignedOutGateHolderSeesTheTestAccountsTheDomainAllows()throws Exception {
        var session=gate();
        domain("/internal/v1/test-sessions/accounts",HttpMethod.GET,"{\"data\":[{\"accountId\":\""+LEARNER+"\",\"username\":\"learner07@lookahead.dev\"}]}",org.springframework.http.HttpStatus.OK);
        mvc.perform(get("/bff/api/v1/auth/test-accounts").session(session)).andExpect(status().isOk())
            .andExpect(jsonPath("data[0].username").value("learner07@lookahead.dev")).andExpect(header().string("Cache-Control","no-store"));
        fixture.server.verify();
        // No open gate in this session: nothing to choose, and the Domain is not asked.
        fixture.server.reset();
        mvc.perform(get("/bff/api/v1/auth/test-accounts").session(new MockHttpSession(context.getServletContext()))).andExpect(status().isOk()).andExpect(jsonPath("data").isEmpty());
        fixture.server.verify();
        // DLV-969 (2026-11-04): signed in as yourself, the account menu's Switch to a test account gets the same list.
        fixture.server.reset();signedInCheck();
        domain("/internal/v1/test-sessions/accounts",HttpMethod.GET,"{\"data\":[{\"accountId\":\""+LEARNER+"\"}]}",org.springframework.http.HttpStatus.OK);
        mvc.perform(get("/bff/api/v1/auth/test-accounts").session(gate()).with(oauth2Login().clientRegistration(registrations.findByRegistrationId("lookahead"))))
            .andExpect(status().isOk()).andExpect(jsonPath("data[0].accountId").value(LEARNER));
    }

    @Test void aTestSessionCallsTheDomainAsTheTestAccountAndSignOutKeepsTheGate()throws Exception {
        var session=started(gate());
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/auth/me"))
            .andExpect(MockRestRequestMatchers.header(TestSessionController.SECRET_HEADER,settings.gatewaySecret())).andExpect(MockRestRequestMatchers.header(TestSessionController.HOLDER_HEADER,"sub-admin"))
            .andExpect(MockRestRequestMatchers.header(TestSessionController.ACCOUNT_HEADER,LEARNER)).andExpect(headerDoesNotExist("Authorization"))
            .andRespond(withSuccess("{\"data\":{\"accountId\":\""+LEARNER+"\"}}",MediaType.APPLICATION_JSON));
        // Routes that need a signed-in person accept the test session too.
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/admin/accounts")).andExpect(MockRestRequestMatchers.header(TestSessionController.ACCOUNT_HEADER,LEARNER))
            .andExpect(headerDoesNotExist("Authorization")).andRespond(withSuccess("{\"data\":[]}",MediaType.APPLICATION_JSON));
        mvc.perform(get("/bff/api/v1/auth/me").session(session)).andExpect(status().isOk()).andExpect(jsonPath("data.accountId").value(LEARNER));
        mvc.perform(get("/bff/api/v1/admin/accounts").session(session)).andExpect(status().isOk());
        fixture.server.verify();
        // A test account has no sign-in, profile or password of its own.
        mvc.perform(get("/api/v1/account/sign-ins").session(session)).andExpect(status().isConflict()).andExpect(jsonPath("code").value("TEST_SESSION"));
        // Sign out: no provider involved, back to /sign-in, the gate admission carried into the fresh session.
        var out=mvc.perform(post("/bff/api/v1/auth/logout").session(session).header("X-CSRF-TOKEN",csrf(session)))
            .andExpect(status().isOk()).andExpect(jsonPath("data.logoutUrl").value("https://learn.example.test/sign-in")).andReturn();
        var fresh=(MockHttpSession)out.getRequest().getSession(false);
        assertThat(fresh).isNotNull();assertThat(fresh.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        assertThat(fresh.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        mvc.perform(get("/bff/api/v1/auth/me").session(fresh)).andExpect(status().isUnauthorized());
    }

    @Test void aTestSessionWhoseGateIsGoneSendsNothingToTheDomain()throws Exception {
        var session=started(gate());
        session.removeAttribute(DevAdmission.ATTRIBUTE);
        mvc.perform(get("/bff/api/v1/auth/me").session(session)).andExpect(status().isUnauthorized());
        fixture.server.verify();
    }

    @Test void startIsRefusedWithoutTheGateForABadIdOrWhenTheDomainSaysNo()throws Exception {
        var noGate=new MockHttpSession(context.getServletContext());
        mvc.perform(post("/bff/api/v1/auth/test-session").session(noGate).header("X-CSRF-TOKEN",csrf(noGate)).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isUnauthorized()).andExpect(jsonPath("code").value("DEV_ADMISSION_REQUIRED"));
        var session=gate();String token=csrf(session);
        for(String body:new String[]{"{\"accountId\":\"not-a-uuid\"}","{}"})
            mvc.perform(post("/bff/api/v1/auth/test-session").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isUnprocessableEntity());
        // Without the CSRF token nothing starts.
        mvc.perform(post("/bff/api/v1/auth/test-session").session(session).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isForbidden());
        domain("/internal/v1/test-sessions/start",HttpMethod.POST,"{\"code\":\"TEST_SESSION_FORBIDDEN\",\"message\":\"Your role cannot use this test account.\"}",org.springframework.http.HttpStatus.FORBIDDEN);
        mvc.perform(post("/bff/api/v1/auth/test-session").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isForbidden()).andExpect(jsonPath("code").value("TEST_SESSION_FORBIDDEN"));
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        fixture.server.verify();fixture.server.reset();
        domain("/internal/v1/test-sessions/start",HttpMethod.POST,"{}",org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR);
        mvc.perform(post("/bff/api/v1/auth/test-session").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isServiceUnavailable());
        fixture.server.verify();
        fixture.server.reset();fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/test-sessions/start")).andRespond(withException(new java.io.IOException("down")));
        mvc.perform(post("/bff/api/v1/auth/test-session").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+LEARNER+"\"}"))
            .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("code").value("SERVICE_UNAVAILABLE"));
    }

    static final String SECOND = "7d1c0b9a-2e3f-4a5b-9c8d-1e2f3a4b5c6d";

    /** Switches this session to {@code account}, signed in as yourself ({@code staff}) or already in a test session. */
    void switchTo(MockHttpSession session,String account,boolean staff)throws Exception {
        domain("/internal/v1/test-sessions/start",HttpMethod.POST,"{\"data\":{\"accountId\":\""+account+"\"}}",org.springframework.http.HttpStatus.OK);
        var request=post("/bff/api/v1/auth/test-session").session(session).contentType(MediaType.APPLICATION_JSON).content("{\"accountId\":\""+account+"\"}");
        if(staff)request.with(oauth2Login().clientRegistration(registrations.findByRegistrationId("lookahead"))).with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf());
        else request.header("X-CSRF-TOKEN",csrf(session));
        mvc.perform(request).andExpect(status().isOk()).andExpect(jsonPath("data.next").value("/"));
        fixture.server.verify();fixture.server.reset();
    }
    /** The staff sign-in's tokens in the session, as the real sign-in stores them (the test login keeps them for one request). */
    void keepTokens(MockHttpSession session){
        var staff=(org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken)session.getAttribute(TestSessionController.STAFF_SIGN_IN);
        var request=new MockHttpServletRequest();request.setSession(session);
        var token=new org.springframework.security.oauth2.core.OAuth2AccessToken(org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER,
            "synthetic-access-token",Instant.now(),Instant.now().plusSeconds(600));
        authorizedClients.saveAuthorizedClient(new org.springframework.security.oauth2.client.OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),staff.getName(),token),
            staff,request,new MockHttpServletResponse());
    }
    org.springframework.security.core.Authentication signedIn(MockHttpSession session){
        return ((SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
    }

    /** DLV-969 (owner, 2026-11-04): Switch to a test account from the account menu, switch again, then Back to my account. */
    @Test void staffSwitchFromTheirOwnSignInAndComeBackWithoutSigningIn()throws Exception {
        var session=gate();signedInCheck();
        String before=session.getId();
        switchTo(session,LEARNER,true);
        keepTokens(session);
        assertThat(session.getId()).isNotEqualTo(before);
        assertThat(TestSessionController.active(signedIn(session))).isTrue();
        var staff=session.getAttribute(TestSessionController.STAFF_SIGN_IN);
        assertThat(staff).isInstanceOf(org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken.class);
        assertThat(session.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        mvc.perform(get("/bff/api/v1/auth/test-session").session(session)).andExpect(status().isOk())
            .andExpect(jsonPath("data.active").value(true)).andExpect(jsonPath("data.canReturn").value(true)).andExpect(header().string("Cache-Control","no-store"));
        // Switching between test accounts keeps the same staff sign-in aside.
        switchTo(session,SECOND,false);
        assertThat(signedIn(session).getPrincipal()).isEqualTo(SECOND);
        assertThat(session.getAttribute(TestSessionController.STAFF_SIGN_IN)).isSameAs(staff);
        // Back to my account: your own sign-in again, with a new session id, and nothing kept aside.
        String during=session.getId();signedInCheck();
        mvc.perform(post("/bff/api/v1/auth/test-session/end").session(session).header("X-CSRF-TOKEN",csrf(session)))
            .andExpect(status().isOk()).andExpect(jsonPath("data.next").value("/"));
        assertThat(session.getId()).isNotEqualTo(during);
        assertThat(signedIn(session)).isSameAs(staff);
        assertThat(session.getAttribute(TestSessionController.STAFF_SIGN_IN)).isNull();
        assertThat(session.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        mvc.perform(get("/bff/api/v1/auth/test-session").session(session)).andExpect(status().isOk())
            .andExpect(jsonPath("data.active").value(false)).andExpect(jsonPath("data.canReturn").value(false));
        // Not in a test session: nothing to end.
        mvc.perform(post("/bff/api/v1/auth/test-session/end").session(session).header("X-CSRF-TOKEN",csrf(session)))
            .andExpect(status().isConflict()).andExpect(jsonPath("code").value("NO_TEST_SESSION"));
        // Without the CSRF token, Back to my account does nothing.
        fixture.server.reset();
        var another=started(gate());
        mvc.perform(post("/bff/api/v1/auth/test-session/end").session(another)).andExpect(status().isForbidden());
        assertThat(TestSessionController.active(signedIn(another))).isTrue();
    }

    /** A test session begun signed out has no staff sign-in to return to: Back to my account ends it, as Sign out does. */
    @Test void backFromATestSessionStartedSignedOutGoesToTheSignInPage()throws Exception {
        var session=started(gate());
        mvc.perform(get("/bff/api/v1/auth/test-session").session(session)).andExpect(jsonPath("data.active").value(true)).andExpect(jsonPath("data.canReturn").value(false));
        var out=mvc.perform(post("/bff/api/v1/auth/test-session/end").session(session).header("X-CSRF-TOKEN",csrf(session)))
            .andExpect(status().isOk()).andExpect(jsonPath("data.next").value("/sign-in")).andReturn();
        var fresh=(MockHttpSession)out.getRequest().getSession(false);
        assertThat(fresh.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();assertThat(fresh.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        // The gate gone: the session no longer counts as a test session.
        var gone=started(gate());gone.removeAttribute(DevAdmission.ATTRIBUTE);
        mvc.perform(get("/bff/api/v1/auth/test-session").session(gone)).andExpect(status().isOk()).andExpect(jsonPath("data.active").value(false));
    }

    /** Sign out while a test account is in use, after switching from your own sign-in, signs you out of your own sign-in too. */
    @Test void signOutFromASwitchedTestSessionEndsTheStaffSignIn()throws Exception {
        var session=gate();signedInCheck();
        switchTo(session,LEARNER,true);
        keepTokens(session);
        // The staff sign-in's own sign-out: the Domain ends that sign-in, with its token, not the test account's headers.
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/logout")).andExpect(method(HttpMethod.POST))
            .andExpect(MockRestRequestMatchers.header("Authorization","Bearer synthetic-access-token"))
            .andRespond(withSuccess("{\"data\":{}}",MediaType.APPLICATION_JSON));
        var out=mvc.perform(post("/bff/api/v1/auth/logout").session(session).header("X-CSRF-TOKEN",csrf(session)))
            .andExpect(status().isOk()).andExpect(jsonPath("data.logoutUrl").value("https://learn.example.test/bff/logout/complete")).andReturn();
        var fresh=(MockHttpSession)out.getRequest().getSession(false);
        assertThat(fresh.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        assertThat(fresh.getAttribute(TestSessionController.STAFF_SIGN_IN)).isNull();
        assertThat(fresh.getAttribute(DevAdmission.ATTRIBUTE)).isNotNull();
        fixture.server.verify();
    }
}
