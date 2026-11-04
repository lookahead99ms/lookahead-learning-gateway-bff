package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class LogicalSignInFilterTest {
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @ParameterizedTest @ValueSource(strings={"/bff/api/v1/auth/csrf", "/bff/api/v1/auth/me", "/bff/author/previews/index.html"})
    void revokedSignInCannotUseAnyPrivateBffSurface(String path) throws Exception { check(path, 401); }

    @ParameterizedTest @ValueSource(ints={200, 403, 500, 503})
    void validityAndStorageFailureAreFailClosed(int status) throws Exception { check("/bff/api/v1/auth/me", status); }

    private void check(String path, int status) throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var registration = ClientRegistration.withRegistrationId("lookahead").clientId("test")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
                .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        var client = new OAuth2AuthorizedClient(registration, "account",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"server-only-token",Instant.now(),Instant.now().plusSeconds(300)));
        when(manager.authorize(any())).thenReturn(client);
        var authentication = new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        var settings = new OAuthSettings("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var filter = new LogicalSignInFilter(manager, builder.build(), settings);
        server.expect(requestTo("http://domain/api/v1/auth/me")).andExpect(header("Authorization", "Bearer server-only-token"))
                .andExpect(headerDoesNotExist("Cookie")).andRespond(withStatus(HttpStatus.valueOf(status)));
        var request = new MockHttpServletRequest("GET",path);
        var session = new MockHttpSession(); request.setSession(session);
        var response = new MockHttpServletResponse(); var reached = new AtomicBoolean();
        var lines = capture(() -> filter.doFilter(request,response,(req,res)->reached.set(true)));
        // DLV-969: a failed check is one line saying why; a passed one is silent.
        if (status == 200) assertThat(lines).isEmpty();
        else {
            assertThat(lines).hasSize(1);
            assertThat(lines.getFirst().getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(lines.getFirst().getFormattedMessage()).isEqualTo(status == 401
                    ? "Sign-in check failed for GET " + path + ": DOMAIN_SIGN_IN_ENDED, Domain says this sign-in has ended or was revoked; the learner sign-in ends"
                    : "Sign-in check failed for GET " + path + ": DOMAIN_CHECK_FAILED, Domain answered HTTP " + status + "; answered 503");
            assertThat(OpsLogTest.pairs(lines.getFirst())).contains("event.action=sign-in.check", "upstream.status=" + status,
                    "event.outcome=" + (status == 401 ? "refused" : "failure"));
        }
        assertThat(reached.get()).isEqualTo(status == 200);
        assertThat(session.isInvalid()).isEqualTo(status == 401);
        if(status != 200) assertThat(response.getStatus()).isEqualTo(status == 401 ? 401 : 503);
        assertThat(response.getContentAsString()).doesNotContain("server-only-token");
        server.verify();
    }

    interface Action { void run() throws Exception; }
    static java.util.List<ch.qos.logback.classic.spi.ILoggingEvent> capture(Action action) throws Exception {
        var events = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("lookahead.event");
        var appender = new ch.qos.logback.core.read.ListAppender<ch.qos.logback.classic.spi.ILoggingEvent>(); appender.start(); events.addAppender(appender);
        try { action.run(); } finally { events.detachAppender(appender); }
        for (var line : appender.list) assertThat(line.getFormattedMessage() + OpsLogTest.pairs(line)).doesNotContain("server-only-token", "synthetic-secret");
        return appender.list;
    }

    /** DLV-969: an expired refresh, a failed refresh, no stored tokens and an unreachable Domain each say so. */
    @org.junit.jupiter.api.Test
    void everyFailedCheckSaysWhy() throws Exception {
        var settings = new OAuthSettings("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        SecurityContextHolder.getContext().setAuthentication(
                new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
        var expected = new java.util.LinkedHashMap<Object, String>();
        expected.put(new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", "synthetic-secret", null)),
                "Sign-in check failed for GET /bff/api/v1/plans: SESSION_EXPIRED, Cognito refused the refresh token (invalid_grant); the learner sign-in ends");
        expected.put(new OAuth2AuthorizationException(new OAuth2Error("server_error")),
                "Sign-in check failed for GET /bff/api/v1/plans: TOKEN_REFRESH_FAILED, the token refresh did not succeed; answered 503");
        expected.put("no client", "Sign-in check failed for GET /bff/api/v1/plans: NO_PROVIDER_TOKENS, this session holds no provider tokens; the learner sign-in ends");
        expected.put(new IllegalStateException("synthetic-secret"),
                "Sign-in check failed for GET /bff/api/v1/plans: DOMAIN_UNAVAILABLE, Domain did not answer (IllegalStateException); answered 503");
        for (var entry : expected.entrySet()) {
            if (entry.getKey() instanceof RuntimeException failure) when(manager.authorize(any())).thenThrow(failure);
            else doReturn(null).when(manager).authorize(any());
            var request = new MockHttpServletRequest("GET", "/bff/api/v1/plans"); request.setSession(new MockHttpSession());
            var lines = capture(() -> new LogicalSignInFilter(manager, RestClient.builder().build(), settings)
                    .doFilter(request, new MockHttpServletResponse(), (req, res) -> {}));
            assertThat(lines).extracting(ch.qos.logback.classic.spi.ILoggingEvent::getFormattedMessage).containsExactly(entry.getValue());
            reset(manager);
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
        }
    }

    /** DLV-969 S37: a passed check is reused for a minute on API reads, for the same person; writes, CSRF and previews always ask. */
    @org.junit.jupiter.api.Test
    void aPassedCheckIsReusedForAMinuteOnApiCallsForTheSamePersonOnly() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var registration = ClientRegistration.withRegistrationId("lookahead").clientId("test")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
                .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, "account",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-only-token", Instant.now(), Instant.now().plusSeconds(300))));
        var settings = new OAuthSettings("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var now = new java.util.concurrent.atomic.AtomicReference<>(Instant.parse("2026-11-03T12:00:00Z"));
        var clock = new java.time.Clock() {
            public java.time.ZoneId getZone() { return java.time.ZoneOffset.UTC; }
            public java.time.Clock withZone(java.time.ZoneId zone) { return this; }
            public Instant instant() { return now.get(); }
        };
        var filter = new LogicalSignInFilter(manager, builder.build(), settings, clock);
        server.expect(org.springframework.test.web.client.ExpectedCount.times(6), requestTo("http://domain/api/v1/auth/me"))
                .andRespond(withStatus(HttpStatus.OK));
        var session = new MockHttpSession();
        java.util.function.BiFunction<String, String, Boolean> call = (person, target) -> {
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", person), "sub"), Set.of(), "lookahead"));
            String[] parts = target.split(" ", 2);
            var request = parts.length == 2 ? new MockHttpServletRequest(parts[0], parts[1]) : new MockHttpServletRequest("GET", target);
            request.setSession(session);
            var reached = new AtomicBoolean();
            try { filter.doFilter(request, new MockHttpServletResponse(), (req, res) -> reached.set(true)); }
            catch (Exception failure) { throw new IllegalStateException(failure); }
            return reached.get();
        };
        assertThat(call.apply("account", "/bff/api/v1/auth/me")).isTrue();            // asks the Domain (1)
        now.set(now.get().plusSeconds(59));
        assertThat(call.apply("account", "/bff/api/v1/plans")).isTrue();              // reused
        assertThat(call.apply("account", "/bff/author/previews/index.html")).isTrue(); // previews always ask (2)
        assertThat(call.apply("account", "POST /bff/api/v1/plans")).isTrue();         // writes always ask (3)
        assertThat(call.apply("account", "/bff/api/v1/auth/csrf")).isTrue();          // the CSRF token always asks (4)
        assertThat(call.apply("someone-else", "/bff/api/v1/plans")).isTrue();         // another person asks (5)
        now.set(now.get().plusSeconds(61));
        assertThat(call.apply("account", "/bff/api/v1/plans")).isTrue();              // a minute later, asks again (6)
        server.verify();
    }
}
