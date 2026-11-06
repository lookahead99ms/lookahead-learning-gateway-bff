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
import org.springframework.http.MediaType;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
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
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Real cloud Spring security/controller boundary; all provider and Domain HTTP is controlled. */
@SpringBootTest(classes=CloudGatewaySecurityIntegrationTest.Application.class, properties={
    "spring.config.name=cloud-security-test", "app.deployment-environment=dev",
    "app.oauth.frontend=https://learn.example.test", "app.oauth.domain-api-upstream=https://domain.example.test",
    "app.oauth.client-id=syntheticclient12345", "app.oauth.client-secret=synthetic-client-secret-never-used-outside-fixtures",
    "app.cognito.issuer=https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example",
    "app.cognito.managed-login=https://example.auth.us-east-2.amazoncognito.com",
    "app.cognito.scope-prefix=lookahead", "app.cognito.gateway-secret=synthetic-internal-secret-never-used-outside-fixtures"})
@ActiveProfiles("gateway")
class CloudGatewaySecurityIntegrationTest {
    @Configuration @EnableAutoConfiguration
    @Import({GatewayConfiguration.class,GatewayClientConfiguration.class,OAuthPropertiesConfiguration.class,
        GatewayController.class,CloudAccountController.class,PasswordSignInController.class,IdentityProxyController.class,
        AccountProxyController.class,AccountMergeProxyController.class,GatewayErrorHandler.class,ControlledHttp.class})
    static class Application {}
    @Configuration static class ControlledHttp {
        MockRestServiceServer server;
        @Bean @Primary RestClient controlledHttp(){var builder=RestClient.builder();server=MockRestServiceServer.bindTo(builder).build();return builder.build();}
    }
    @Autowired WebApplicationContext context;
    @Autowired ControlledHttp fixture;
    @Autowired OAuthSettings settings;
    @Autowired ClientRegistrationRepository registrations;
    @Autowired OAuth2AuthorizedClientRepository clients;
    @Autowired GatewaySecurityHandlers handlers;
    @Autowired RestClient http;
    MockMvc mvc;
    @BeforeEach void reset(){fixture.server.reset();mvc=MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();SecurityContextHolder.clearContext();}
    MockHttpSession session(boolean restricted)throws Exception {
        var session=new MockHttpSession(context.getServletContext());
        mvc.perform(get("/api/v1/auth/csrf").session(session).with(oauth2Login().clientRegistration(registrations.findByRegistrationId("lookahead")))).andExpect(status().isOk());
        var request=new MockHttpServletRequest();request.setSession(session);CloudGatewaySessions.proof(request,true);
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",Instant.now(),Instant.now().plusSeconds(300)),
            new OAuth2RefreshToken("synthetic-refresh",Instant.now())),auth,request,new MockHttpServletResponse());
        if(restricted)session.setAttribute(CloudGatewaySessions.CHALLENGE,"c".repeat(43));
        return session;
    }
    String csrf(MockHttpSession session)throws Exception{return new JsonMapper().readTree(mvc.perform(get("/api/v1/auth/csrf").session(session)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data").path("token").asString();}
    void upstream(String action,String json){fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/"+action))
        .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("Authorization","Bearer synthetic-access")).andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("X-LookAhead-Gateway-Secret",settings.gatewaySecret()))
        .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("X-LookAhead-SignIn-Proof",org.hamcrest.Matchers.matchesPattern("[A-Za-z0-9_-]{43}")))
        .andRespond(withSuccess(json,MediaType.APPLICATION_JSON));}

    @Test void cloudContextSelectsCloudAccountControllerAndKeepsLocalProxyChainAbsent()throws Exception {
        assertThat(context.getBeansOfType(CloudAccountController.class)).hasSize(1);
        assertThat(context.getBeansOfType(IdentityProxyController.class)).isEmpty();
        assertThat(context.getBeansOfType(AccountProxyController.class)).isEmpty();
        assertThat(context.containsBean("identityProxySecurity")).isFalse();
        assertThat(settings.identityUpstream()).isNull();
        mvc.perform(get("/api/v1/auth/options")).andExpect(status().isOk())
            .andExpect(jsonPath("$.data.managedLogin").value(true))
            .andExpect(jsonPath("$.data.registration").value(true)).andExpect(jsonPath("$.data.password").value(true));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .content("username=synthetic&password=never-used")).andExpect(status().isForbidden());
    }

    @Test void cloudLoginUsesPkceFreshAuthenticationAndSafeReturn()throws Exception {
        mvc.perform(get("/oauth2/authorization/lookahead")).andExpect(status().isFound())
            .andExpect(header().string("Location",org.hamcrest.Matchers.allOf(org.hamcrest.Matchers.startsWith(settings.managedLogin()+"/oauth2/authorize?"),org.hamcrest.Matchers.containsString("prompt=login"),org.hamcrest.Matchers.containsString("code_challenge_method=S256"),org.hamcrest.Matchers.containsString("state="),org.hamcrest.Matchers.containsString("nonce="),org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString(settings.clientSecret())))));
        var session=new MockHttpSession();
        mvc.perform(get("/bff/login").param("returnTo","//attacker.test/").session(session)).andExpect(status().isFound());
        assertThat(session.getAttribute("learningReturnTo")).isEqualTo("/");
    }
    @Test void callbackWithoutMatchingAuthorizationStateFailsBeforeProviderOrDomainCalls()throws Exception {
        mvc.perform(get("/login/oauth2/code/lookahead").param("code","synthetic-code").param("state","unmatched-state"))
            .andExpect(redirectedUrl(settings.frontend()+"/sign-in?error=oauth"));
        fixture.server.verify();
    }
    @Test void cloudMutationsRequireOwnSessionCsrfBeforeAnyUpstreamCall()throws Exception {
        var session=session(false);String token=csrf(session), other=csrf(session(false));
        var events=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var capture=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();capture.start();events.addAppender(capture);
        try {
            for(String path:new String[]{"/api/v1/account/profile","/api/v1/account/password","/api/v1/account/sign-ins/revoke","/api/v1/auth/sign-in-challenge/replace"}){
                mvc.perform(post(path).session(session).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
                mvc.perform(post(path).session(session).header("X-CSRF-TOKEN",other).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
            }
        } finally {events.detachAppender(capture);}
        // DLV-969: each REQUEST_REJECTED says which check failed, as a reason code; never the token or the exception's type name.
        assertThat(capture.list).hasSize(8).allSatisfy(line->{
            assertThat(line.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(line.getFormattedMessage()).doesNotContain(other).doesNotContain("Exception");
        });
        assertThat(capture.list.get(0).getFormattedMessage()).isEqualTo("Request rejected with REQUEST_REJECTED: POST /api/v1/account/profile (no CSRF token was sent, or it does not match this session's)");
        assertThat(capture.list).allSatisfy(line->assertThat(OpsLogTest.pairs(line)).contains("event.action=request.rejected","reason=CSRF_TOKEN_MISMATCH"));
        assertThat(GatewaySecurityHandlers.rejection(new org.springframework.security.web.csrf.MissingCsrfTokenException(null))).isEqualTo("CSRF_NO_SESSION_TOKEN");
        assertThat(GatewaySecurityHandlers.rejection(new org.springframework.security.web.csrf.CsrfException("x"))).isEqualTo("CSRF_REJECTED");
        assertThat(GatewaySecurityHandlers.rejection(new org.springframework.security.access.AccessDeniedException("x"))).isEqualTo("ROUTE_NOT_ALLOWED");
        upstream("profile","{\"data\":{\"displayName\":\"Learner\"}}");
        mvc.perform(post("/api/v1/account/profile").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"displayName\":\"Learner\"}")).andExpect(status().isOk());fixture.server.verify();
    }
    @Test void restrictedChallengeCannotReadOrWriteApplicationDataAndSurvivesBootstrap()throws Exception {
        var session=session(true);String token=csrf(session);
        for(String path:new String[]{"/bff/api/v1/auth/me","/bff/api/v1/plans","/bff/author/previews/architecture/index.html","/content/protected.json","/api/v1/account/profile","/api/v1/account/sign-ins"})
            mvc.perform(get(path).session(session)).andExpect(status().isUnauthorized());
        mvc.perform(post("/bff/api/v1/plans").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isUnauthorized());
        mvc.perform(get("/bff/api/v1/auth/csrf").session(session)).andExpect(status().isOk());
        assertThat(session.isInvalid()).isFalse();assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isEqualTo("c".repeat(43));
        upstream("challenge","{\"data\":{\"limit\":2,\"signIns\":[]}}");
        mvc.perform(get("/api/v1/auth/sign-in-challenge").session(session)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.not(org.hamcrest.Matchers.containsString("c".repeat(43)))));fixture.server.verify();
    }
    @Test void replacementKeepsRetrySecretUntilVerifiedResumeWithoutProviderRoundTrip()throws Exception {
        var session=session(true);String token=csrf(session);
        upstream("replace","{\"data\":{\"accountId\":\"owner\"}}");
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/auth/me")).andRespond(withSuccess("{}",MediaType.APPLICATION_JSON));
        mvc.perform(post("/api/v1/auth/sign-in-challenge/replace").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"signInId\":\"selected\"}")).andExpect(status().isOk());
        assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNotNull();
        mvc.perform(get("/bff/login").session(session).param("returnTo","/learn/modern-java")).andExpect(redirectedUrl(settings.frontend()+"/learn/modern-java"));
        assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNull();fixture.server.verify();
    }
    @Test void failedAdmissionClearsProviderTokensAndBrowserSession()throws Exception {
        var session=session(false);var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withServerError());
        handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=admission");assertThat(session.isInvalid()).isTrue();fixture.server.verify();
    }
    @Test void failedAdmissionKeepsTheDevGateAdmissionSoTheSignInPageExplains()throws Exception {
        // DLV-968 (2026-11-02): in DEV the learner rejection must not drop the gate admission, or the browser lands on /dev/access.
        var session=session(false);var now=java.time.Instant.parse("2026-11-02T08:00:00Z");
        var admission=new DevAdmission.State("author@lookahead.dev","010b25a0-c0f1-709c-467f-06e036639814",now);
        session.setAttribute(DevAdmission.ATTRIBUTE,admission);
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN));
        handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=admission");assertThat(session.isInvalid()).isTrue();
        var replacement=request.getSession(false);
        assertThat(replacement).isNotNull().isNotSameAs(session);
        assertThat(replacement.getAttribute(DevAdmission.ATTRIBUTE)).isEqualTo(admission);
        assertThat(replacement.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        assertThat(replacement.getMaxInactiveInterval()).isEqualTo(8*3600);fixture.server.verify();
    }
    @Test void waitingAccountKeepsTheGateAndLandsOnThePendingNotice()throws Exception {
        // DLV-969: Domain's 403 ACCOUNT_ADMISSION_REQUIRED ends the learner sign-in, keeps the DEV gate and shows the landing notice.
        var session=session(false);var now=Instant.parse("2026-11-02T08:00:00Z");
        var admission=new DevAdmission.State("author@lookahead.dev","010b25a0-c0f1-709c-467f-06e036639814",now);
        session.setAttribute(DevAdmission.ATTRIBUTE,admission);
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"ACCOUNT_ADMISSION_REQUIRED\",\"message\":\"Sign in again or contact the account administrator.\"}"));
        handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/?access=pending");assertThat(session.isInvalid()).isTrue();
        var replacement=request.getSession(false);
        assertThat(replacement).isNotNull().isNotSameAs(session);
        assertThat(replacement.getAttribute(DevAdmission.ATTRIBUTE)).isEqualTo(admission);
        assertThat(replacement.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        assertThat(clients.<OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",auth,request)).isNull();fixture.server.verify();
        // Any other 403 keeps the sign-in page explanation.
        fixture.server.reset();
        var other=session(false);var otherRequest=new MockHttpServletRequest();otherRequest.setSession(other);var otherResponse=new MockHttpServletResponse();
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"RECENT_AUTHENTICATION_REQUIRED\"}"));
        handlers.loginSucceeded(otherRequest,otherResponse,((org.springframework.security.core.context.SecurityContext)other.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication());
        assertThat(otherResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=admission");assertThat(other.isInvalid()).isTrue();fixture.server.verify();
    }
    org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken oidcSignIn(Instant now,Instant authTime){
        var claims=new java.util.HashMap<String,Object>(java.util.Map.of("sub","010b25a0-c0f1-709c-467f-06e036639814","cognito:username","author@lookahead.dev"));
        if(authTime!=null)claims.put("auth_time",authTime);
        var token=new org.springframework.security.oauth2.core.oidc.OidcIdToken("synthetic-id-token",now.minusSeconds(5),now.plusSeconds(3600),claims);
        var user=new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")),token);
        return new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user,user.getAuthorities(),"lookahead");
    }
    @Test void waitingAccountCarriesItsFirstNameToTheWelcomePageInACookie()throws Exception {
        // DLV-971: the sign-in ends, no session survives, so the first name rides in a short-lived cookie, not in the URL.
        var now=Instant.now();
        var claims=new java.util.HashMap<String,Object>(java.util.Map.of("sub","010b25a0-c0f1-709c-467f-06e036639814","cognito:username","mohiddin@lookahead.dev","given_name","Mohiddin","family_name","Shaik","auth_time",now.minusSeconds(3)));
        var token=new org.springframework.security.oauth2.core.oidc.OidcIdToken("synthetic-id-token",now.minusSeconds(5),now.plusSeconds(3600),claims);
        var user=new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")),token);
        var auth=new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user,user.getAuthorities(),"lookahead");
        var session=new MockHttpSession(context.getServletContext());
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,request,response);
        var gated=new GatewaySecurityHandlers(settings,clients,http,java.util.Optional.of(DevGate.freshSignIn(java.time.Clock.systemUTC())));
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"ACCOUNT_ADMISSION_REQUIRED\",\"message\":\"Sign in again or contact the account administrator.\"}"));
        gated.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/welcome?access=pending");
        assertThat(request.getSession(false)).isNull();
        var cookie=response.getHeader("Set-Cookie");
        assertThat(cookie).startsWith("lookahead-welcome=Mohiddin;").contains("Path=/").contains("Max-Age=900").contains("SameSite=Strict").doesNotContain("HttpOnly");
        fixture.server.verify();
        // Any other refusal sets no cookie.
        fixture.server.reset();
        var other=new MockHttpServletRequest();other.setSession(new MockHttpSession(context.getServletContext()));var otherResponse=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,other,otherResponse);
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"RECENT_AUTHENTICATION_REQUIRED\"}"));
        gated.loginSucceeded(other,otherResponse,auth);
        assertThat(otherResponse.getHeader("Set-Cookie")).isNull();fixture.server.verify();
    }
    @Test void firstNameComesFromTheClaimsAndIsLettersOnly() {
        java.util.function.Function<java.util.Map<String,Object>,org.springframework.security.core.Authentication> signIn=extra->{
            var claims=new java.util.HashMap<String,Object>(java.util.Map.of("sub","s"));claims.putAll(extra);
            var token=new org.springframework.security.oauth2.core.oidc.OidcIdToken("t",Instant.now().minusSeconds(5),Instant.now().plusSeconds(60),claims);
            var user=new org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser(java.util.List.of(new org.springframework.security.core.authority.SimpleGrantedAuthority("ROLE_USER")),token);
            return new org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken(user,user.getAuthorities(),"lookahead");};
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("given_name","Mohiddin","name","Mohiddin Shaik")))).isEqualTo("Mohiddin");
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("name","Shree  Ram")))).isEqualTo("Shree");
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("given_name"," Zoë-Anne ")))).isEqualTo("Zoë-Anne");
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("given_name","R2D2")))).isNull();
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("given_name","a".repeat(41))))).isNull();
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of("given_name","<b>x</b>")))).isNull();
        assertThat(GatewaySecurityHandlers.firstName(signIn.apply(java.util.Map.of()))).isNull();
        assertThat(GatewaySecurityHandlers.firstName(null)).isNull();
    }
    @Test void devGateOpensBeforeDomainIsAskedAndTheGrantSurvivesTheSignIn()throws Exception {
        // DLV-969: with the lower-cost-dev gate present a fresh Look Ahead sign-in opens DEV first; Domain then admits the account.
        var order=new java.util.ArrayList<String>();var now=Instant.now();var auth=oidcSignIn(now,now.minusSeconds(3));
        var session=new MockHttpSession(context.getServletContext());session.setAttribute("learningReturnTo","/learn");
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,request,response);
        DevGate real=DevGate.freshSignIn(java.time.Clock.systemUTC());
        var gated=new GatewaySecurityHandlers(settings,clients,http,java.util.Optional.of((r,u)->{order.add("gate");real.admit(r,u);}));
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit"))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("Authorization","Bearer synthetic-access"))
            .andRespond(sent->{order.add("domain");return withSuccess("{\"data\":{\"signInId\":\"s1\"}}",MediaType.APPLICATION_JSON).createResponse(sent);});
        String before=session.getId();
        gated.loginSucceeded(request,response,auth);
        assertThat(order).containsExactly("gate","domain");
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/learn");
        assertThat(session.isInvalid()).isFalse();assertThat(session.getId()).isNotEqualTo(before);assertThat(session.getMaxInactiveInterval()).isEqualTo(8*3600);
        assertThat(session.getAttribute(DevAdmission.ATTRIBUTE)).isEqualTo(new DevAdmission.State("author@lookahead.dev","010b25a0-c0f1-709c-467f-06e036639814",((DevAdmission.State)session.getAttribute(DevAdmission.ATTRIBUTE)).admittedAt()));
        assertThat(clients.<OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",auth,request)).isNotNull();fixture.server.verify();
        // A stale sign-in never opens the gate; the learner sign-in ends before Domain is asked.
        fixture.server.reset();
        var stale=new MockHttpServletRequest();stale.setSession(new MockHttpSession(context.getServletContext()));var staleResponse=new MockHttpServletResponse();
        new GatewaySecurityHandlers(settings,clients,http,java.util.Optional.of(real)).loginSucceeded(stale,staleResponse,oidcSignIn(now,now.minusSeconds(600)));
        // DLV-969: no gate was open before, so the person sees the gate page's notice (the Web sign-in page is behind the gate).
        assertThat(staleResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/dev/access?error=signin");assertThat(stale.getSession(false)).isNull();fixture.server.verify();
    }
    /** DLV-969, README decision 2: a waiting account never gets DEV, even where this browser held an open gate before. */
    /** DLV-969: the password routes need no sign-in but always need the session CSRF token; bad input never reaches Cognito. */
    @Test void passwordRoutesAreAnonymousButCsrfProtected() throws Exception {
        mvc.perform(post("/bff/api/v1/auth/password/sign-in").contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        var session=new org.springframework.mock.web.MockHttpSession(context.getServletContext());
        String token=csrf(session);
        mvc.perform(post("/bff/api/v1/auth/password/sign-in").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("INVALID_REQUEST"));
        mvc.perform(post("/bff/api/v1/auth/password/challenge").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content("{\"code\":\"123456\"}"))
            .andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value("STEP_EXPIRED"));
    }
    @Test void devGateClosesForAWaitingAccount()throws Exception {
        var now=Instant.now();var auth=oidcSignIn(now,now.minusSeconds(3));
        var session=new MockHttpSession(context.getServletContext());
        var earlier=new DevAdmission.State("someone-else","subject-before",now.minusSeconds(60));session.setAttribute(DevAdmission.ATTRIBUTE,earlier);
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,request,response);
        var gated=new GatewaySecurityHandlers(settings,clients,http,java.util.Optional.of(DevGate.freshSignIn(java.time.Clock.systemUTC())));
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"ACCOUNT_ADMISSION_REQUIRED\"}"));
        var events=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var capture=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();capture.start();events.addAppender(capture);
        try {gated.loginSucceeded(request,response,auth);} finally {events.detachAppender(capture);}
        // DLV-969: the waiting account is logged as Domain's refusal code, in words, with the provider and the door.
        var waiting=capture.list.getLast();
        assertThat(waiting.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
        assertThat(waiting.getFormattedMessage()).isEqualTo("Sign-in refused by Domain (password via password-page): ACCOUNT_ADMISSION_REQUIRED, the account is waiting for the owner to admit it");
        assertThat(OpsLogTest.pairs(waiting)).contains("event.action=sign-in.completed","event.outcome=refused","reason=ACCOUNT_ADMISSION_REQUIRED","upstream.status=403");
        assertThat(capture.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).noneMatch(m->m.contains("author@lookahead.dev")||m.contains("synthetic-access"));
        // DLV-969: the waiting account lands on the Web welcome page (the Look Ahead essence), not the gate card.
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/welcome?access=pending");
        assertThat(request.getSession(false)).isNull();
        assertThat(clients.<OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",auth,request)).isNull();fixture.server.verify();
        // Any other refusal puts back the gate this browser held before, so its owner sees the sign-in page explanation.
        fixture.server.reset();
        var held=new MockHttpSession(context.getServletContext());held.setAttribute(DevAdmission.ATTRIBUTE,earlier);
        var heldRequest=new MockHttpServletRequest();heldRequest.setSession(held);var heldResponse=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,heldRequest,heldResponse);
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withServerError());
        capture.list.clear();events.addAppender(capture);
        try {gated.loginSucceeded(heldRequest,heldResponse,auth);} finally {events.detachAppender(capture);}
        assertThat(capture.list.getLast().getFormattedMessage()).isEqualTo("Sign-in refused (password via password-page): DOMAIN_REFUSED");
        assertThat(OpsLogTest.pairs(capture.list.getLast())).contains("upstream.status=500");
        assertThat(heldResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=admission");
        assertThat(heldRequest.getSession(false).getAttribute(DevAdmission.ATTRIBUTE)).isEqualTo(earlier);fixture.server.verify();
        // A failed provider sign-in outside an open gate returns to the gate page; inside one, to the Web sign-in page.
        var outside=new MockHttpServletRequest();var outsideResponse=new MockHttpServletResponse();
        capture.list.clear();events.addAppender(capture);
        try {
            gated.loginFailed(outside,outsideResponse,new org.springframework.security.authentication.BadCredentialsException("synthetic"));
            gated.loginFailed(new MockHttpServletRequest(),new MockHttpServletResponse(),new org.springframework.security.oauth2.core.OAuth2AuthenticationException(
                new org.springframework.security.oauth2.core.OAuth2Error("invalid_state_parameter","synthetic description",null)));
        } finally {events.detachAppender(capture);}
        assertThat(capture.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage)
            .containsExactly("OAuth sign-in failed at the callback: authentication_failed","OAuth sign-in failed at the callback: invalid_state_parameter");
        assertThat(OpsLogTest.pairs(capture.list.getLast())).contains("reason=OAUTH_INVALID_STATE_PARAMETER");
        assertThat(outsideResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/dev/access?error=signin");
        var inside=new MockHttpServletRequest();inside.getSession().setAttribute(DevAdmission.ATTRIBUTE,earlier);var insideResponse=new MockHttpServletResponse();
        gated.loginFailed(inside,insideResponse,new org.springframework.security.authentication.BadCredentialsException("synthetic"));
        assertThat(insideResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=oauth");
    }
    @Test void challengeAdmissionPreservesSafeDestinationAndNeverReturnsSecrets()throws Exception {
        var session=session(false);session.setAttribute("learningReturnTo","/study-plan?view=week");var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        upstream("admit","{\"data\":{\"challengeToken\":\""+"c".repeat(43)+"\"}}");handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in/choose?returnTo=%2Fstudy-plan%3Fview%3Dweek");
        assertThat(response.getContentAsString()).doesNotContain("synthetic-access","c".repeat(43));fixture.server.verify();
    }
    /** DLV-969 S36: a redirect sign-in admitted with a literal mergeAvailable true goes to the merge offer instead of its target. */
    @Test void admittedSignInWithMergeAvailableGoesToTheMergeOffer()throws Exception {
        String token="abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z";
        record Case(String admit,String returnTo,String expected){}
        for(var c:java.util.List.of(
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":true}}","/learn","/account/merge?offer=1"),
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":false}}","/learn","/learn"),
                new Case("{\"data\":{\"signInId\":\"s1\"}}","/learn","/learn"),
                // Only a JSON boolean counts; a string or number is ignored.
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":\"true\"}}","/learn","/learn"),
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":1}}","/learn","/learn"),
                // Already heading to the merge page from the email link: the token stays.
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":true}}","/account/merge?token="+token,"/account/merge?token="+token),
                new Case("{\"data\":{\"signInId\":\"s1\"}}","/account/merge?token="+token,"/account/merge?token="+token),
                // A bare merge target gets the offer; an existing offer stays as it is.
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":true}}","/account/merge","/account/merge?offer=1"),
                new Case("{\"data\":{\"signInId\":\"s1\",\"mergeAvailable\":true}}","/account/merge?offer=1","/account/merge?offer=1"),
                new Case("{\"data\":{\"signInId\":\"s1\"}}","/account/merge","/account/merge"))) {
            fixture.server.reset();
            var session=session(false);session.setAttribute("learningReturnTo",c.returnTo());
            var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
            var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
            upstream("admit",c.admit());
            var events=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("lookahead.event");
            var logged=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();logged.start();events.addAppender(logged);
            try { handlers.loginSucceeded(request,response,auth); } finally { events.detachAppender(logged); }
            assertThat(response.getRedirectedUrl()).as(c.admit()+" "+c.returnTo()).isEqualTo(settings.frontend()+c.expected());
            assertThat(session.isInvalid()).isFalse();fixture.server.verify();
            // DLV-969 log: the completion line says whether the merge was offered; the offer redirect is one more INFO line, only for a literal true.
            boolean offered=c.admit().contains("\"mergeAvailable\":true");
            var completed=logged.list.stream().filter(l->OpsLogTest.pairs(l).contains("event.action=sign-in.completed")).findFirst().orElseThrow();
            assertThat(OpsLogTest.pairs(completed)).as(c.admit()).contains("merge.available="+offered);
            assertThat(completed.getFormattedMessage()).as(c.admit()).startsWith("Sign-in completed (").contains("): Domain admitted the account");
            assertThat(completed.getFormattedMessage().endsWith(" and other accounts share its verified email (merge offered)")).as(c.admit()).isEqualTo(offered);
            var offers=logged.list.stream().filter(l->OpsLogTest.pairs(l).contains("event.action=sign-in.merge-offer")).toList();
            assertThat(offers).as(c.admit()).hasSize(offered?1:0);
            if(offered)assertThat(offers.getFirst().getFormattedMessage()).isEqualTo("Sign-in completed and other accounts share this person's verified email: redirected to the merge offer page");
            assertThat(logged.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).noneMatch(m->m.contains(token));
        }
    }
    /** DLV-969 S36: without a gate (PROD) a waiting account lands on the landing notice, never on the merge offer. */
    @Test void prodWaitingAccountNeverGoesToTheMergeOffer()throws Exception {
        var session=session(false);session.setAttribute("learningReturnTo","/learn");
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"ACCOUNT_ADMISSION_REQUIRED\",\"data\":{\"mergeAvailable\":true}}"));
        handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/?access=pending");
        assertThat(GatewaySecurityHandlers.mergeAvailable(request)).isFalse();fixture.server.verify();
    }
    /** DLV-969 S36: a sign-in still at the challenge goes to /sign-in/choose and carries no offer, even when Domain says mergeAvailable. */
    @Test void signInAtTheChallengeCarriesNoMergeOffer()throws Exception {
        var session=session(false);session.setAttribute("learningReturnTo","/learn");session.setAttribute(GatewaySecurityHandlers.MERGE_AFTER_CHALLENGE,Boolean.TRUE);
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        var auth=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        upstream("admit","{\"data\":{\"challengeToken\":\""+"c".repeat(43)+"\",\"mergeAvailable\":true}}");
        handlers.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in/choose?returnTo=%2Flearn");
        assertThat(GatewaySecurityHandlers.mergeAvailable(request)).isFalse();
        // A leftover offer from an earlier challenge never carries over to this one.
        assertThat(request.getSession().getAttribute(GatewaySecurityHandlers.MERGE_AFTER_CHALLENGE)).isNull();fixture.server.verify();
    }
    /** DLV-969 S36: the replace answer's literal mergeAvailable true is relayed, and the /bff/login that completes the challenge sends the offer once. */
    @Test void resolvedChallengeWithMergeAvailableGoesToTheMergeOffer()throws Exception {
        String token="abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z";
        record Case(String replace,boolean relayed,String returnTo,String expected){}
        for(var c:java.util.List.of(
                new Case("{\"data\":{\"accountId\":\"owner\",\"mergeAvailable\":true}}",true,"/learn/modern-java","/account/merge?offer=1"),
                new Case("{\"data\":{\"accountId\":\"owner\",\"mergeAvailable\":true}}",true,"/account/merge","/account/merge?offer=1"),
                new Case("{\"data\":{\"accountId\":\"owner\",\"mergeAvailable\":true}}",true,"/account/merge?token="+token,"/account/merge?token="+token),
                new Case("{\"data\":{\"accountId\":\"owner\",\"mergeAvailable\":false}}",false,"/learn/modern-java","/learn/modern-java"),
                new Case("{\"data\":{\"accountId\":\"owner\",\"mergeAvailable\":\"true\"}}",false,"/learn/modern-java","/learn/modern-java"),
                new Case("{\"data\":{\"accountId\":\"owner\"}}",false,"/learn/modern-java","/learn/modern-java"))) {
            fixture.server.reset();
            var session=session(true);String csrf=csrf(session);
            upstream("replace",c.replace());
            fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/auth/me")).andRespond(withSuccess("{}",MediaType.APPLICATION_JSON));
            var answer=mvc.perform(post("/api/v1/auth/sign-in-challenge/replace").session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content("{\"signInId\":\"selected\"}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.accountId").value("owner"));
            if(c.relayed())answer.andExpect(jsonPath("$.data.mergeAvailable").value(true));else answer.andExpect(jsonPath("$.data.mergeAvailable").doesNotExist());
            mvc.perform(get("/bff/login").session(session).param("returnTo",c.returnTo())).andExpect(redirectedUrl(settings.frontend()+c.expected()));
            assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNull();
            assertThat(session.getAttribute(GatewaySecurityHandlers.MERGE_AFTER_CHALLENGE)).as(c.replace()).isNull();fixture.server.verify();
            // Used once: a later page-load sign-in reuse goes to its normal target.
            fixture.server.reset();
            fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/auth/me")).andRespond(withSuccess("{}",MediaType.APPLICATION_JSON));
            mvc.perform(get("/bff/login").session(session).param("returnTo","/learn")).andExpect(redirectedUrl(settings.frontend()+"/learn"));fixture.server.verify();
        }
    }
    /** DLV-969 S36: a waiting account always lands on /welcome, never on the merge offer, whatever Domain's body says. */
    @Test void waitingAccountNeverGoesToTheMergeOffer()throws Exception {
        var now=Instant.now();var auth=oidcSignIn(now,now.minusSeconds(3));
        var session=new MockHttpSession(context.getServletContext());session.setAttribute("learningReturnTo","/learn");
        var request=new MockHttpServletRequest();request.setSession(session);var response=new MockHttpServletResponse();
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registrations.findByRegistrationId("lookahead"),auth.getName(),
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-access",now,now.plusSeconds(300))),auth,request,response);
        var gated=new GatewaySecurityHandlers(settings,clients,http,java.util.Optional.of(DevGate.freshSignIn(java.time.Clock.systemUTC())));
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/admit")).andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN)
            .contentType(MediaType.APPLICATION_JSON).body("{\"status\":403,\"code\":\"ACCOUNT_ADMISSION_REQUIRED\",\"data\":{\"mergeAvailable\":true}}"));
        gated.loginSucceeded(request,response,auth);
        assertThat(response.getRedirectedUrl()).isEqualTo(settings.frontend()+"/welcome?access=pending");
        assertThat(GatewaySecurityHandlers.mergeAvailable(request)).isFalse();fixture.server.verify();
    }
    /** DLV-969 S36: the Web's same-origin merge routes reach Domain's account routes with the server-held token and proof. */
    org.springframework.test.web.client.ResponseActions mergeUpstream(String path,org.springframework.http.HttpMethod method){
        return fixture.server.expect(requestTo(settings.domainApiUpstream()+path))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.method(method))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("Authorization","Bearer synthetic-access"))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("X-LookAhead-SignIn-Proof",org.hamcrest.Matchers.matchesPattern("[A-Za-z0-9_-]{43}")))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist("X-LookAhead-Gateway-Secret"))
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist("Cookie"));
    }
    @Test void mergeRoutesAreForwardedToDomainWithStatusAndBodyUnchanged()throws Exception {
        String token="abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z", keep="{\"keepAccountId\":\"2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a\"}";
        var session=session(false);String csrf=csrf(session);
        mergeUpstream("/api/v1/account/merge/request",org.springframework.http.HttpMethod.POST)
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.content().string("{}"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.ACCEPTED).contentType(MediaType.APPLICATION_JSON).body("{\"data\":{}}"));
        mergeUpstream("/api/v1/account/merge/"+token,org.springframework.http.HttpMethod.GET)
            .andRespond(withSuccess("{\"data\":{\"email\":\"p@example.test\",\"candidates\":[]}}",MediaType.APPLICATION_JSON));
        mergeUpstream("/api/v1/account/merge/"+token,org.springframework.http.HttpMethod.POST)
            .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.content().string(keep))
            .andRespond(withSuccess("{\"data\":{\"keptAccountId\":\"2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a\"}}",MediaType.APPLICATION_JSON));
        var events=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var logged=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();logged.start();events.addAppender(logged);
        try {
            mvc.perform(post("/api/v1/account/merge/request").session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isAccepted()).andExpect(content().json("{\"data\":{}}")).andExpect(header().string("Cache-Control","no-store"));
            mvc.perform(get("/api/v1/account/merge/"+token).session(session)).andExpect(status().isOk()).andExpect(jsonPath("$.data.email").value("p@example.test"));
            mvc.perform(post("/api/v1/account/merge/"+token).session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(keep))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.keptAccountId").value("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
            fixture.server.verify();
            // DLV-969 log: one INFO line per merge step, like the other account actions; never the token, email or account id.
            assertThat(logged.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).containsExactly(
                "Merge step merge.request accepted by Domain: if there is anything to merge, the link is on its way by email",
                "Merge step merge.candidates done: Domain listed the accounts behind the emailed link",
                "Merge step merge.merge done: Domain merged the accounts; this sign-in ends");
            assertThat(OpsLogTest.pairs(logged.list.get(2))).contains("event.action=merge.merge","event.outcome=success","upstream.status=200");
            assertThat(logged.list).allMatch(line->line.getLevel()==ch.qos.logback.classic.Level.INFO);
            logged.list.clear();
            // Domain's refusals come back as Domain sent them, not as the Gateway's own answer; each is one WARN line with Domain's code.
            for(int status:new int[]{400,404,409,422}) {
                fixture.server.reset();
                String body="{\"status\":"+status+",\"code\":\"FROM_DOMAIN_"+status+"\"}";
                mergeUpstream("/api/v1/account/merge/"+token,org.springframework.http.HttpMethod.POST).andRespond(withStatus(org.springframework.http.HttpStatus.valueOf(status)).contentType(MediaType.APPLICATION_JSON).body(body));
                mvc.perform(post("/api/v1/account/merge/"+token).session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content(keep))
                    .andExpect(status().is(status)).andExpect(content().json(body));
                fixture.server.verify();
                var line=logged.list.getLast();
                assertThat(line.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
                assertThat(line.getFormattedMessage()).isEqualTo("Merge step merge.merge refused by Domain: FROM_DOMAIN_"+status+" (HTTP "+status+")");
                assertThat(OpsLogTest.pairs(line)).contains("event.action=merge.merge","event.outcome=refused","reason=FROM_DOMAIN_"+status,"upstream.status="+status);
            }
            assertThat(logged.list).hasSize(4);logged.list.clear();
            fixture.server.reset();
            mergeUpstream("/api/v1/account/merge/"+token,org.springframework.http.HttpMethod.GET)
                .andRespond(withStatus(org.springframework.http.HttpStatus.NOT_FOUND).contentType(MediaType.APPLICATION_JSON).body("{\"status\":404,\"code\":\"MERGE_TOKEN_INVALID\",\"message\":\"from Domain\"}"));
            mvc.perform(get("/api/v1/account/merge/"+token).session(session)).andExpect(status().isNotFound()).andExpect(jsonPath("$.message").value("from Domain"));
            fixture.server.verify();
            assertThat(logged.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).containsExactly("Merge step merge.candidates refused by Domain: MERGE_TOKEN_INVALID (HTTP 404)");
            logged.list.clear();
            // Domain unreachable: the Gateway's own 503, never a stack trace; the line names the exception types only.
            fixture.server.reset();
            mergeUpstream("/api/v1/account/merge/request",org.springframework.http.HttpMethod.POST).andRespond(sent->{throw new java.io.IOException("synthetic outage");});
            mvc.perform(post("/api/v1/account/merge/request").session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isServiceUnavailable()).andExpect(jsonPath("$.code").value("SERVICE_UNAVAILABLE"));
            fixture.server.verify();
            var outage=logged.list.getLast();
            assertThat(outage.getFormattedMessage()).startsWith("Merge step merge.request refused: SERVICE_UNAVAILABLE (Domain did not answer (").doesNotContain("synthetic outage");
            assertThat(OpsLogTest.pairs(outage)).contains("event.action=merge.request","event.outcome=failure","reason=SERVICE_UNAVAILABLE","http.status=503");
            assertThat(logged.list).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).noneMatch(m->m.contains(token)||m.contains("p@example.test")||m.contains("2c7e9a4d"));
        } finally { events.detachAppender(logged); }
    }
    @Test void mergeRoutesRefuseBeforeDomainWithoutSignInCsrfOrAWellFormedToken()throws Exception {
        String token="abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z";
        // Signed out: 401 from the security chain.
        mvc.perform(get("/api/v1/account/merge/"+token)).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("AUTHENTICATION_REQUIRED"));
        var anonymous=new MockHttpSession(context.getServletContext());String anonymousCsrf=csrf(anonymous);
        mvc.perform(post("/api/v1/account/merge/request").session(anonymous).header("X-CSRF-TOKEN",anonymousCsrf).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isUnauthorized());
        // Signed in, but a POST without this session's CSRF token is rejected.
        var session=session(false);String other=csrf(session(false));
        for(String path:new String[]{"/api/v1/account/merge/request","/api/v1/account/merge/"+token}) {
            mvc.perform(post(path).session(session).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
            mvc.perform(post(path).session(session).header("X-CSRF-TOKEN",other).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        }
        // A token that is not 43 url-safe characters never reaches Domain.
        String csrf=csrf(session);
        for(String bad:new String[]{"short",token+"x","request"}) {
            mvc.perform(get("/api/v1/account/merge/"+bad).session(session)).andExpect(status().isNotFound()).andExpect(jsonPath("$.code").value("MERGE_TOKEN_INVALID"));
        }
        mvc.perform(post("/api/v1/account/merge/"+token.substring(1)+".").session(session).header("X-CSRF-TOKEN",csrf).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isNotFound());
        // A session at the sign-in challenge has no account routes yet; the refusal is one WARN line with its code.
        var restricted=session(true);String restrictedCsrf=csrf(restricted);
        var events=(ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var logged=new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>();logged.start();events.addAppender(logged);
        try {
            mvc.perform(post("/api/v1/account/merge/request").session(restricted).header("X-CSRF-TOKEN",restrictedCsrf).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("SIGN_IN_CHALLENGE_REQUIRED"));
            var line=logged.list.stream().filter(l->OpsLogTest.pairs(l).contains("event.action=merge.request")).findFirst().orElseThrow();
            assertThat(line.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(line.getFormattedMessage()).isEqualTo("Merge step merge.request refused: SIGN_IN_CHALLENGE_REQUIRED (the person must first choose which active sign-in to end)");
            assertThat(OpsLogTest.pairs(line)).contains("event.outcome=refused","reason=SIGN_IN_CHALLENGE_REQUIRED","http.status=401");
        } finally { events.detachAppender(logged); }
        fixture.server.verify();
    }
    @Test void domainFailurePreservesSessionInsteadOfClaimingLogout()throws Exception {
        var session=session(false);String token=csrf(session);
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/logout")).andRespond(withServerError());
        mvc.perform(post("/bff/api/v1/auth/logout").session(session).header("X-CSRF-TOKEN",token)).andExpect(status().isServiceUnavailable());
        assertThat(session.isInvalid()).isFalse();fixture.server.verify();
    }
    @Test void requestParameterCannotReuseASignInRejectedByDomain()throws Exception {
        for(String value:new String[]{"false","TRUE","1",""}) {
            fixture.server.reset();
            var session=session(true);
            fixture.server.expect(requestTo(settings.domainApiUpstream()+"/api/v1/auth/me"))
                .andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.header("Authorization","Bearer synthetic-access"))
                .andRespond(withStatus(org.springframework.http.HttpStatus.UNAUTHORIZED));
            mvc.perform(get("/bff/login").session(session).param("reauthenticate",value).param("returnTo","/study-plan"))
                .andExpect(redirectedUrl(settings.frontend()+"/oauth2/authorization/lookahead"));
            assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNotNull();
            assertThat(session.getAttribute("learningReturnTo")).isEqualTo("/study-plan");
            fixture.server.verify();
        }
    }
    @Test void forcedReauthenticationStartsOAuthWithoutGrantingAccess()throws Exception {
        var session=session(true);
        mvc.perform(get("/bff/login").session(session).param("reauthenticate","true").param("returnTo","//attacker.test/"))
            .andExpect(redirectedUrl(settings.frontend()+"/oauth2/authorization/lookahead"));
        assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNotNull();
        assertThat(session.getAttribute("learningReturnTo")).isEqualTo("/");
        fixture.server.verify(); // No Domain call or token-reuse path was taken.
    }
    @Test void anonymousLoginParametersAlwaysStartOAuth()throws Exception {
        for(String value:new String[]{"true","false","TRUE",""}) {
            var session=new MockHttpSession(context.getServletContext());
            mvc.perform(get("/bff/login").session(session).param("reauthenticate",value))
                .andExpect(redirectedUrl(settings.frontend()+"/oauth2/authorization/lookahead"));
        }
        fixture.server.verify();
    }
    @Test void authenticatedSessionWithoutStoredClientCannotReuseSignIn()throws Exception {
        var session=session(true);
        var request=new MockHttpServletRequest();request.setSession(session);
        var authentication=((org.springframework.security.core.context.SecurityContext)session.getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
        clients.removeAuthorizedClient("lookahead",authentication,request,new MockHttpServletResponse());
        mvc.perform(get("/bff/login").session(session).param("reauthenticate","false"))
            .andExpect(redirectedUrl(settings.frontend()+"/oauth2/authorization/lookahead"));
        assertThat(session.getAttribute(CloudGatewaySessions.CHALLENGE)).isNotNull();
        fixture.server.verify();
    }
    @Test void durableLogoutClearsSessionEvenWhenProviderRevocationIsUnavailable()throws Exception {
        var session=session(false);String token=csrf(session);
        upstream("logout","{\"data\":{\"signedOut\":true}}");
        fixture.server.expect(requestTo(settings.managedLogin()+"/oauth2/revoke")).andExpect(org.springframework.test.web.client.match.MockRestRequestMatchers.content().string(org.hamcrest.Matchers.containsString("token=synthetic-refresh"))).andRespond(withServerError());
        mvc.perform(post("/bff/api/v1/auth/logout").session(session).header("X-CSRF-TOKEN",token)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("/bff/logout/complete"))).andExpect(content().string(org.hamcrest.Matchers.containsString("false")));
        assertThat(session.isInvalid()).isTrue();fixture.server.verify();
        mvc.perform(get("/bff/logout/complete")).andExpect(redirectedUrl(settings.managedLogin()+"/logout?client_id="+settings.clientId()+"&logout_uri="+java.net.URLEncoder.encode(settings.frontend()+"/sign-in",java.nio.charset.StandardCharsets.UTF_8)));
    }
    @Test void confirmedPasswordChangeInvalidatesGatewaySessionWhileUnconfirmedChangePreservesIt()throws Exception {
        var session=session(false);String token=csrf(session);
        fixture.server.expect(requestTo(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/password"))
            .andRespond(withStatus(org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE).body("{\"code\":\"SERVICE_UNAVAILABLE\"}").contentType(MediaType.APPLICATION_JSON));
        upstream("password","{\"data\":{\"reauthenticationRequired\":true}}");
        String body="{\"currentPassword\":\"synthetic current\",\"newPassword\":\"synthetic new password\",\"confirmPassword\":\"synthetic new password\"}";
        mvc.perform(post("/api/v1/account/password").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isServiceUnavailable());
        assertThat(session.isInvalid()).isFalse();
        mvc.perform(post("/api/v1/account/password").session(session).header("X-CSRF-TOKEN",token).contentType(MediaType.APPLICATION_JSON).content(body)).andExpect(status().isOk()).andExpect(content().string(org.hamcrest.Matchers.containsString("reauthenticationRequired")));
        assertThat(session.isInvalid()).isTrue();fixture.server.verify();
    }
}
