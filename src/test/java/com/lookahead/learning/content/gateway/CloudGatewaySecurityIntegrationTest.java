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
        AccountProxyController.class,GatewayErrorHandler.class,ControlledHttp.class})
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
        for(String path:new String[]{"/api/v1/account/profile","/api/v1/account/password","/api/v1/account/sign-ins/revoke","/api/v1/auth/sign-in-challenge/replace"}){
            mvc.perform(post(path).session(session).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
            mvc.perform(post(path).session(session).header("X-CSRF-TOKEN",other).contentType(MediaType.APPLICATION_JSON).content("{}")).andExpect(status().isForbidden());
        }
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
        gated.loginSucceeded(request,response,auth);
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
        gated.loginSucceeded(heldRequest,heldResponse,auth);
        assertThat(heldResponse.getRedirectedUrl()).isEqualTo(settings.frontend()+"/sign-in?error=admission");
        assertThat(heldRequest.getSession(false).getAttribute(DevAdmission.ATTRIBUTE)).isEqualTo(earlier);fixture.server.verify();
        // A failed provider sign-in outside an open gate returns to the gate page; inside one, to the Web sign-in page.
        var outside=new MockHttpServletRequest();var outsideResponse=new MockHttpServletResponse();
        gated.loginFailed(outside,outsideResponse,new org.springframework.security.authentication.BadCredentialsException("synthetic"));
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
