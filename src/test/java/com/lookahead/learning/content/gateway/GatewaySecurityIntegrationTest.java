package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthPropertiesConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.WebApplicationContext;
import tools.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = GatewaySecurityIntegrationTest.Application.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {"spring.config.name=security-test", "app.deployment-environment=local",
                "app.oauth.issuer=http://127.0.0.1:4331", "app.oauth.frontend=http://127.0.0.1:4331",
                "app.oauth.client-secret=synthetic-long-client-secret-for-testing", "app.oauth.client-id=lookahead-test-gateway",
                "app.oauth.identity-upstream=http://identity:8080", "app.oauth.domain-api-upstream=http://domain-api:8080"})
@ActiveProfiles("gateway")
class GatewaySecurityIntegrationTest {
    @LocalServerPort int port;
    @Autowired WebApplicationContext context;
    @Autowired ObjectMapper mapper;
    @Autowired MutationProbe mutationProbe;
    @Autowired ActiveSignInTestConfiguration activeSignIns;
    @org.junit.jupiter.api.BeforeEach void activeByDefault() { activeSignIns.status.set(200); }

    @Test void loadedOldSessionCannotRetrieveCsrfAfterUpstreamRevocation() throws Exception {
        var http = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        var registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lookahead");
        var session = new MockHttpSession(context.getServletContext());
        http.perform(get("/bff/api/v1/auth/csrf").session(session)
                .with(oauth2Login().clientRegistration(registration))).andExpect(status().isOk());
        var authentication = ((org.springframework.security.core.context.SecurityContext) session.getAttribute(
                "SPRING_SECURITY_CONTEXT")).getAuthentication();
        var storedRequest = new org.springframework.mock.web.MockHttpServletRequest();
        storedRequest.setSession(session);
        context.getBean(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository.class)
                .saveAuthorizedClient(new org.springframework.security.oauth2.client.OAuth2AuthorizedClient(
                        registration, authentication.getName(), new org.springframework.security.oauth2.core.OAuth2AccessToken(
                        org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER, "synthetic-stored-token",
                        java.time.Instant.now(), java.time.Instant.now().plusSeconds(300))),
                        authentication, storedRequest, new org.springframework.mock.web.MockHttpServletResponse());
        activeSignIns.status.set(401);
        http.perform(get("/bff/api/v1/auth/csrf").session(session))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("AUTHENTICATION_REQUIRED")));
        assertThat(session.isInvalid()).isTrue();
    }

    @Test void loadedRevokedSessionCannotSubmitAuthorReviewWithPreviouslyValidCsrf() throws Exception {
        var http = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        var registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lookahead");
        var session = new MockHttpSession(context.getServletContext());
        String csrf = mapper.readTree(http.perform(get("/bff/api/v1/auth/csrf").session(session)
                .with(oauth2Login().clientRegistration(registration))).andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).path("data").path("token").asText();
        int writesBefore = mutationProbe.acceptedWrites.get();
        var authentication = ((org.springframework.security.core.context.SecurityContext) session.getAttribute(
                "SPRING_SECURITY_CONTEXT")).getAuthentication();
        var storedRequest = new org.springframework.mock.web.MockHttpServletRequest();
        storedRequest.setSession(session);
        context.getBean(org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository.class)
                .saveAuthorizedClient(new org.springframework.security.oauth2.client.OAuth2AuthorizedClient(
                        registration, authentication.getName(), new org.springframework.security.oauth2.core.OAuth2AccessToken(
                        org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER, "synthetic-stored-token",
                        java.time.Instant.now(), java.time.Instant.now().plusSeconds(300))),
                        authentication, storedRequest, new org.springframework.mock.web.MockHttpServletResponse());
        activeSignIns.status.set(401);
        http.perform(post("/bff/api/v1/author/review-artifacts/dlv-704/events").session(session).header("X-CSRF-TOKEN", csrf))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("AUTHENTICATION_REQUIRED")));
        assertThat(session.isInvalid()).isTrue();
        assertThat(mutationProbe.acceptedWrites).hasValue(writesBefore);
    }

    @Configuration
    @EnableAutoConfiguration(excludeName = {
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @Import({ActiveSignInTestConfiguration.class, GatewayConfiguration.class, GatewayClientConfiguration.class, OAuthPropertiesConfiguration.class,
            GatewayController.class, MutationProbe.class})
    static class Application { }

    // A test-only mutation target proves whether the real security chain reached
    // a handler. Storage and the outbound Domain API are outside this test.
    @RestController
    static class MutationProbe {
        final AtomicInteger acceptedWrites = new AtomicInteger();

        @PostMapping({"/bff/api/v1/plans", "/bff/api/v1/author/review-artifacts/dlv-704/events"})
        String mutate(OAuth2AuthenticationToken authentication) {
            assertThat(authentication.isAuthenticated()).isTrue();
            acceptedWrites.incrementAndGet();
            return "accepted";
        }
    }

    @Test void assembledGatewayRedirectUsesPkceAndFixedConfiguredOrigin() throws Exception {
        var response = request("GET", "/oauth2/authorization/lookahead");
        assertThat(response.statusCode()).isEqualTo(302);
        String location = response.headers().firstValue("location").orElseThrow();
        assertThat(location).startsWith("http://127.0.0.1:4331/oauth2/authorize?")
                .contains("code_challenge=", "code_challenge_method=S256", "state=", "nonce=")
                .doesNotContain("client_secret", "synthetic-long-client-secret");
    }

    @Test void assembledGatewayPreservesAuthenticationAndCsrfErrors() throws Exception {
        var anonymous = request("GET", "/bff/api/v1/plans");
        assertThat(anonymous.statusCode()).isEqualTo(401);
        assertThat(anonymous.body()).contains("AUTHENTICATION_REQUIRED");
        assertThat(anonymous.headers().firstValue("cache-control")).contains("no-store");
        var unsafe = request("POST", "/bff/api/v1/plans");
        assertThat(unsafe.statusCode()).isEqualTo(403);
        assertThat(unsafe.body()).contains("REQUEST_REJECTED");
    }

    @Test void invalidCallbackRetainsSafeFailureRedirect() throws Exception {
        var response = request("GET", "/login/oauth2/code/lookahead?code=invalid&state=invalid");
        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(response.headers().firstValue("location")).contains("http://127.0.0.1:4331/sign-in?error=oauth");
    }

    @Test void previewRouteRequiresAuthenticationAndRejectsMutations() throws Exception {
        for (String method : new String[]{"GET", "HEAD"}) {
            var response = request(method, "/bff/author/previews/example/index.html");
            assertThat(response.statusCode()).isEqualTo(401);
            assertThat(response.headers().firstValue("cache-control")).contains("no-store");
            assertThat(response.headers().firstValue("x-frame-options")).contains("DENY");
        }
        assertThat(request("POST", "/bff/author/previews/example/index.html").statusCode()).isEqualTo(403);
    }

    @Test void authenticatedMutationRequiresTheCsrfTokenFromItsOwnSession() throws Exception {
        var http = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        var registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lookahead");
        var firstSession = new MockHttpSession(context.getServletContext());
        var secondSession = new MockHttpSession(context.getServletContext());
        mutationProbe.acceptedWrites.set(0);

        var firstCsrf = http.perform(get("/bff/api/v1/auth/csrf").session(firstSession)
                        .with(oauth2Login().clientRegistration(registration)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        var secondCsrf = http.perform(get("/bff/api/v1/auth/csrf").session(secondSession)
                        .with(oauth2Login().clientRegistration(registration)))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String firstToken = mapper.readTree(firstCsrf).path("data").path("token").asText();
        String secondToken = mapper.readTree(secondCsrf).path("data").path("token").asText();
        assertThat(firstToken).isNotBlank();
        assertThat(secondToken).isNotBlank().isNotEqualTo(firstToken);

        http.perform(post("/bff/api/v1/plans").session(secondSession)
                        .with(oauth2Login().clientRegistration(registration)))
                .andExpect(status().isForbidden())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("REQUEST_REJECTED")));
        assertThat(mutationProbe.acceptedWrites).hasValue(0);

        http.perform(post("/bff/api/v1/plans").session(secondSession)
                        .with(oauth2Login().clientRegistration(registration))
                        .header("X-CSRF-TOKEN", firstToken))
                .andExpect(status().isForbidden())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("REQUEST_REJECTED")));
        assertThat(mutationProbe.acceptedWrites).hasValue(0);

        http.perform(post("/bff/api/v1/plans").session(secondSession)
                        .with(oauth2Login().clientRegistration(registration))
                        .header("X-CSRF-TOKEN", secondToken))
                .andExpect(status().isOk()).andExpect(content().string("accepted"));
        assertThat(mutationProbe.acceptedWrites).hasValue(1);
    }

    @Test void authorReviewRequiresSessionAndSessionBoundCsrf() throws Exception {
        assertThat(request("GET", "/bff/api/v1/author/review-artifacts").statusCode()).isEqualTo(401);
        var http = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        var registration = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lookahead");
        var session = new MockHttpSession(context.getServletContext());
        var otherSession = new MockHttpSession(context.getServletContext());
        String path = "/bff/api/v1/author/review-artifacts/dlv-704/events";
        String own = mapper.readTree(http.perform(get("/bff/api/v1/auth/csrf").session(session)
                .with(oauth2Login().clientRegistration(registration))).andReturn().getResponse().getContentAsString()).path("data").path("token").asText();
        String other = mapper.readTree(http.perform(get("/bff/api/v1/auth/csrf").session(otherSession)
                .with(oauth2Login().clientRegistration(registration))).andReturn().getResponse().getContentAsString()).path("data").path("token").asText();
        http.perform(post(path).session(session).with(oauth2Login().clientRegistration(registration))).andExpect(status().isForbidden());
        http.perform(post(path).session(session).with(oauth2Login().clientRegistration(registration)).header("X-CSRF-TOKEN", other)).andExpect(status().isForbidden());
        http.perform(post(path).session(session).with(oauth2Login().clientRegistration(registration)).header("X-CSRF-TOKEN", own)).andExpect(status().isOk());
    }

    private HttpResponse<String> request(String method, String path) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + path))
                .method(method, HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
    }
}
