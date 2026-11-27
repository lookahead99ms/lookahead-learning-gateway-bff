package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.session.DevAccessGate;
import com.lookahead.gateway.security.session.DevAccessSession;
import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import java.util.Locale;

/**
 * DLV-1015: the failure answers of the sign-in chain, driven directly: the 401 for a request without a sign-in, the 403
 * for a refused request and the redirect after a failed OAuth callback. The four methods moved here, statements
 * unchanged, from the one handler class that also held the success side. The chain drives them in
 * SecurityFilterChainConfigurationIntegrationTest and GatewayBffApplicationCloudIntegrationTest.
 */
class SignInFailureHandlerTest {
    private static final OAuthClientDetails CLOUD = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    private static final DevAccessGate GATE = DevAccessGate.freshSignIn(Clock.systemUTC(), "dev");

    final SignInFailureHandler ungated = new SignInFailureHandler(CLOUD, Optional.empty());
    final SignInFailureHandler gated = new SignInFailureHandler(CLOUD, Optional.of(GATE));

    @Test void aRequestWithoutASignInIsAnswered401AsJsonThatIsNotStored() throws Exception {
        var response = new MockHttpServletResponse();
        try (var log = new LogCapture("lookahead.event")) {
            ungated.authenticationRequired(new MockHttpServletRequest("GET", "/bff/api/v1/plans"), response, new InsufficientAuthenticationException("synthetic"));
            assertThat(log.lines()).isEmpty();
        }
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/json");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in to continue\"}");
    }

    @Test void aRefusedRequestIsAnswered403AndTheLineNamesTheCheckThatRefusedItNeverTheExceptionType() throws Exception {
        var token = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "synthetic-expected");
        var refusals = new LinkedHashMap<AccessDeniedException, String>();
        refusals.put(new MissingCsrfTokenException(null), "CSRF_NO_SESSION_TOKEN (this session holds no CSRF token yet (a new or expired session))");
        refusals.put(new InvalidCsrfTokenException(token, "synthetic-sent"), "CSRF_TOKEN_MISMATCH (no CSRF token was sent, or it does not match this session's)");
        refusals.put(new CsrfException("synthetic"), "CSRF_REJECTED (the CSRF check failed)");
        refusals.put(new AccessDeniedException("synthetic"), "ROUTE_NOT_ALLOWED (this route or method is not allowed for this sign-in)");
        for (Map.Entry<AccessDeniedException, String> refusal : refusals.entrySet()) {
            String reason = refusal.getValue().substring(0, refusal.getValue().indexOf(' '));
            assertThat(SignInFailureHandler.rejection(refusal.getKey())).isEqualTo(reason);
            var response = new MockHttpServletResponse();
            try (var log = new LogCapture("lookahead.event")) {
                ungated.accessDenied(new MockHttpServletRequest("POST", "/bff/api/v1/plans"), response, refusal.getKey());
                assertThat(log.messages()).containsExactly("Request rejected with REQUEST_REJECTED: POST /bff/api/v1/plans: " + refusal.getValue());
                assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
                assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=request.rejected", "event.outcome=refused", "reason=" + reason,
                        "http.method=POST", "url.path=/bff/api/v1/plans");
                log.assertNothing("Exception", "synthetic");
            }
            assertThat(response.getStatus()).isEqualTo(403);
            assertThat(response.getContentType()).isEqualTo("application/json");
            assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
            assertThat(response.getContentAsString()).isEqualTo("{\"code\":\"REQUEST_REJECTED\",\"message\":\"Refresh the security token and retry\"}");
        }
    }

    @Test void aFailedCallbackLogsTheOAuthCodeFromAFixedVocabularyAndNeverItsDescription() throws Exception {
        var failures = new LinkedHashMap<AuthenticationException, String>();
        failures.put(new OAuth2AuthenticationException(new OAuth2Error("access_denied", "synthetic description", null)), "access_denied");
        failures.put(new OAuth2AuthenticationException(new OAuth2Error("Not A Code!", "synthetic description", null)), "authentication_failed");
        failures.put(new OAuth2AuthenticationException(new OAuth2Error("a".repeat(65), "synthetic description", null)), "authentication_failed");
        failures.put(new BadCredentialsException("synthetic description"), "authentication_failed");
        for (Map.Entry<AuthenticationException, String> failure : failures.entrySet()) {
            String code = failure.getValue(), type = failure.getKey().getClass().getSimpleName();
            var response = new MockHttpServletResponse();
            try (var log = new LogCapture("lookahead.event")) {
                ungated.loginFailed(new MockHttpServletRequest(), response, failure.getKey());
                assertThat(log.messages()).containsExactly("OAuth sign-in failed at the callback (via oauth): OAUTH_" + code.toUpperCase(Locale.ROOT)
                        + " (the provider or the callback check answered " + code + "; " + type + ")");
                assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
                assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-in.oauth", "event.outcome=refused",
                        "reason=OAUTH_" + code.toUpperCase(Locale.ROOT), "oauth.code=" + code, "exception.types=" + type);
                log.assertNothing("synthetic description");
            }
            // No DEV gate (local and PROD): always the Web sign-in page.
            assertThat(response.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/sign-in?error=oauth");
        }
    }

    @Test void withTheDevGateTheBrowserReturnsToTheGatePageUnlessThisBrowserHoldsAnOpenGate() throws Exception {
        var failure = new BadCredentialsException("synthetic");
        var outside = new MockHttpServletResponse();
        gated.loginFailed(new MockHttpServletRequest(), outside, failure);
        assertThat(outside.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/dev/access?error=signin");

        var expired = new MockHttpServletRequest();
        expired.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("someone", "subject", Instant.now().minus(DevAccessSession.WINDOW).minusSeconds(60)));
        var afterTheWindow = new MockHttpServletResponse();
        gated.loginFailed(expired, afterTheWindow, failure);
        assertThat(afterTheWindow.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/dev/access?error=signin");

        var open = new MockHttpServletRequest();
        open.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("someone", "subject", Instant.now().minusSeconds(60)));
        var inside = new MockHttpServletResponse();
        gated.loginFailed(open, inside, failure);
        assertThat(inside.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/sign-in?error=oauth");

        // Without a gate the same open-gate session makes no difference.
        var plain = new MockHttpServletResponse();
        ungated.loginFailed(open, plain, failure);
        assertThat(plain.getRedirectedUrl()).isEqualTo(CLOUD.frontend() + "/sign-in?error=oauth");
    }
}
