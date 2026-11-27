package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.util.AccountMergeOffer;
import com.lookahead.gateway.util.SignInReturnDestination;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import java.util.HashMap;
import java.util.Optional;

/**
 * DLV-1015: the redirect after an accepted OAuth sign-in, driven directly. loginSucceeded moved here, statements
 * unchanged, from the one handler class that also held the failure side; the completion it asks is the
 * SignInCompletionHandler bean. The whole callback is driven in GatewayBffApplicationCloudIntegrationTest.
 */
class SignInSuccessHandlerTest {
    private static final OAuthClientDetails CLOUD = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    private static final OAuthClientDetails LOCAL = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-test",
            "synthetic-client-secret-only-for-testing", "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");

    final SignInCompletionHandler completion = mock(SignInCompletionHandler.class);

    static Authentication signIn(Map<String, Object> more) {
        var claims = new HashMap<String, Object>(Map.of("sub", "synthetic-subject"));
        claims.putAll(more);
        var now = Instant.parse("2026-11-02T20:00:00Z");
        var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), new OidcIdToken("synthetic-id-token", now, now.plusSeconds(300), claims));
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");
    }

    @Test void theBrowserGoesToTheFrontendPathTheCompletionReturnsAndNothingIsLogged() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        var authentication = signIn(Map.of());
        when(completion.completeSignIn(request, response, authentication)).thenReturn("/learn/java?step=2");
        try (var log = new LogCapture("lookahead.event")) {
            new SignInSuccessHandler(CLOUD, completion).loginSucceeded(request, response, authentication);
            assertThat(log.lines()).isEmpty();
        }
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/learn/java?step=2");
        verify(completion).completeSignIn(request, response, authentication);
    }

    @Test void anAdmissionWithAMergeOfferSendsTheBrowserToTheMergePageFirstAndSaysSo() throws Exception {
        Map<Authentication, String> providers = Map.of(
                signIn(Map.of("cognito:username", "priya@example.invalid")), "password",
                signIn(Map.of("cognito:username", "Google_1234567890")), "google");
        for (var entry : providers.entrySet()) {
            var request = new MockHttpServletRequest();
            var response = new MockHttpServletResponse();
            doAnswer(call -> {
                call.<HttpServletRequest>getArgument(0).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
                return "/learn";
            }).when(completion).completeSignIn(any(), any(), any());
            try (var log = new LogCapture("lookahead.event")) {
                new SignInSuccessHandler(CLOUD, completion).loginSucceeded(request, response, entry.getKey());
                assertThat(log.messages()).containsExactly("Sign-in completed (" + entry.getValue()
                        + " via oauth) and other accounts share this person's verified email: redirected to the merge offer page");
                assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
                assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-in.merge-offer", "event.outcome=success",
                        "provider=" + entry.getValue(), "via=oauth");
            }
            assertThat(response.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/account/merge?offer=1");
        }
    }

    @Test void aMergeDestinationThatAlreadyCarriesItsQueryIsKeptAndLocalModeNamesTheIdentityService() throws Exception {
        var request = new MockHttpServletRequest();
        var response = new MockHttpServletResponse();
        doAnswer(call -> {
            call.<HttpServletRequest>getArgument(0).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
            return "/account/merge?token=synthetic";
        }).when(completion).completeSignIn(any(), any(), any());
        try (var log = new LogCapture("lookahead.event")) {
            // Local mode never looks at the principal for the provider, so no authentication is needed for the line.
            new SignInSuccessHandler(LOCAL, completion).loginSucceeded(request, response, null);
            assertThat(LogCapture.pairs(log.last())).contains("provider=identity", "via=oauth");
        }
        assertThat(response.getRedirectedUrl()).isEqualTo(LOCAL.frontend() + "/account/merge?token=synthetic");
    }

    @Test void successfulLoginUsesHomeWhenSavedDestinationIsMissingOrInvalid() throws Exception {
        var oauth = new OAuthClientDetails("http://127.0.0.1:4301", "fixture", "synthetic",
                "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4301");
        var handler = new SignInSuccessHandler(oauth, new SignInCompletionHandler(oauth, null, null, Optional.empty()));
        for (Object saved : new Object[] {null, "//outside.example", 123, "/#paths", "/author/architecture"}) {
            var request = new MockHttpServletRequest();
            if (saved != null) request.getSession().setAttribute("learningReturnTo", saved);
            var response = new MockHttpServletResponse();
            handler.loginSucceeded(request, response, null);
            String expected = saved instanceof String value ? SignInReturnDestination.safeReturn(value) : "/";
            assertThat(response.getRedirectedUrl()).isEqualTo("http://127.0.0.1:4301" + expected);
            assertThat(request.getSession().getAttribute("learningReturnTo")).isNull();
        }
    }
}
