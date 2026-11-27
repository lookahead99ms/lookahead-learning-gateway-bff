package com.lookahead.gateway.security.filter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.OpsLogTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.session.SignInProofSession;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiFunction;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class SignInCheckFilterTest {
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
        var oauth = new OAuthClientDetails("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var filter = new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(oauth, builder.build()), oauth);
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
            assertThat(lines.getFirst().getLevel()).isEqualTo(Level.WARN);
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
    static List<ILoggingEvent> capture(Action action) throws Exception {
        var events = (Logger) LoggerFactory.getLogger("lookahead.event");
        var appender = new ListAppender<ILoggingEvent>(); appender.start(); events.addAppender(appender);
        try { action.run(); } finally { events.detachAppender(appender); }
        for (var line : appender.list) assertThat(line.getFormattedMessage() + OpsLogTest.pairs(line)).doesNotContain("server-only-token", "synthetic-secret");
        return appender.list;
    }

    /** DLV-969: an expired refresh, a failed refresh, no stored tokens and an unreachable Domain each say so. */
    @Test
    void everyFailedCheckSaysWhy() throws Exception {
        var oauth = new OAuthClientDetails("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        SecurityContextHolder.getContext().setAuthentication(
                new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
        var expected = new LinkedHashMap<Object, String>();
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
            var lines = capture(() -> new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(oauth, RestClient.builder().build()), oauth)
                    .doFilter(request, new MockHttpServletResponse(), (req, res) -> {}));
            assertThat(lines).extracting(ILoggingEvent::getFormattedMessage).containsExactly(entry.getValue());
            reset(manager);
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
        }
    }

    /** DLV-969 S37: a passed check is reused for a minute on API reads, for the same person; writes, CSRF and previews always ask. */
    @Test
    void aPassedCheckIsReusedForAMinuteOnApiCallsForTheSamePersonOnly() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var registration = ClientRegistration.withRegistrationId("lookahead").clientId("test")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
                .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, "account",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-only-token", Instant.now(), Instant.now().plusSeconds(300))));
        var oauth = new OAuthClientDetails("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
        var now = new AtomicReference<>(Instant.parse("2026-11-03T12:00:00Z"));
        var clock = new Clock() {
            public ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(ZoneId zone) { return this; }
            public Instant instant() { return now.get(); }
        };
        var filter = new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(oauth, builder.build()), oauth, clock);
        server.expect(ExpectedCount.times(6), requestTo("http://domain/api/v1/auth/me"))
                .andRespond(withStatus(HttpStatus.OK));
        var session = new MockHttpSession();
        BiFunction<String, String, Boolean> call = (person, target) -> {
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

    // ---- One check at a time per session (the 500 on 4300, 2026-11-25)
    static final OAuthClientDetails OAUTH = new OAuthClientDetails("http://localhost", "test", "synthetic-secret", "http://identity", "http://domain", "http://localhost");
    static OAuth2AuthorizedClient signedIn() {
        var registration = ClientRegistration.withRegistrationId("lookahead").clientId("test")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
                .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        return new OAuth2AuthorizedClient(registration, "account",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "server-only-token", Instant.now(), Instant.now().plusSeconds(300)));
    }
    /** One request of the signed-in person on its own thread; answers the status, or 200 when the chain was reached. */
    static Future<Integer> send(ExecutorService threads, SignInCheckFilter filter, MockHttpSession session, String method, String path) {
        return threads.submit(() -> {
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
            try {
                var request = new MockHttpServletRequest(method, path); request.setSession(session);
                var response = new MockHttpServletResponse(); var reached = new AtomicBoolean();
                filter.doFilter(request, response, (req, res) -> reached.set(true));
                return reached.get() ? 200 : response.getStatus();
            } finally { SecurityContextHolder.clearContext(); }
        });
    }

    @Test
    void requestsOfOneSessionAreCheckedOneAtATimeAndAWaitingReadUsesTheResult() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(ExpectedCount.once(), requestTo("http://domain/api/v1/auth/me")).andRespond(withStatus(HttpStatus.OK));
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var firstInside = new CountDownLatch(1); var release = new CountDownLatch(1);
        var checks = new AtomicInteger();
        when(manager.authorize(any())).thenAnswer(call -> {
            checks.incrementAndGet(); firstInside.countDown();
            assertThat(release.await(5, TimeUnit.SECONDS)).isTrue();
            return signedIn();
        });
        var filter = new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(OAUTH, builder.build()), OAUTH);
        var session = new MockHttpSession();
        var threads = Executors.newFixedThreadPool(4);
        try {
            var first = send(threads, filter, session, "GET", "/bff/api/v1/admin/test-accounts");
            assertThat(firstInside.await(5, TimeUnit.SECONDS)).isTrue();
            var waiting = List.of(send(threads, filter, session, "GET", "/bff/api/v1/admin/accounts"),
                    send(threads, filter, session, "GET", "/bff/api/v1/admin/access"), send(threads, filter, session, "GET", "/bff/api/v1/admin/access/catalog"));
            Thread.sleep(150); // the three wait behind the first: none of them may start its own check
            assertThat(checks.get()).isEqualTo(1);
            release.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS)).isEqualTo(200);
            for (var request : waiting) assertThat(request.get(5, TimeUnit.SECONDS)).isEqualTo(200);
            assertThat(checks.get()).as("the readers that waited used the first request's result").isEqualTo(1);
            assertThat(session.isInvalid()).isFalse();
            server.verify();
        } finally { threads.shutdownNow(); }
    }

    @Test
    void aRequestThatWaitedWhileTheSignInEndedIsToldToSignInAgainNotAnError() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(ExpectedCount.once(), requestTo("http://domain/api/v1/auth/me")).andRespond(withStatus(HttpStatus.UNAUTHORIZED));
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var firstInside = new CountDownLatch(1); var release = new CountDownLatch(1);
        when(manager.authorize(any())).thenAnswer(call -> { firstInside.countDown(); release.await(5, TimeUnit.SECONDS); return signedIn(); });
        var filter = new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(OAUTH, builder.build()), OAUTH);
        var session = new MockHttpSession();
        var threads = Executors.newFixedThreadPool(2);
        try {
            var first = send(threads, filter, session, "GET", "/bff/api/v1/admin/access");
            assertThat(firstInside.await(5, TimeUnit.SECONDS)).isTrue();
            var second = send(threads, filter, session, "GET", "/bff/api/v1/admin/test-accounts");
            Thread.sleep(100);
            release.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS)).isEqualTo(401);
            assertThat(second.get(5, TimeUnit.SECONDS)).as("401 Sign in again, never a 500").isEqualTo(401);
            assertThat(session.isInvalid()).isTrue();
            verify(manager, times(1)).authorize(any());
            server.verify();
        } finally { threads.shutdownNow(); }
    }

    @Test
    void aSessionThatEndsWhileItIsCheckedAnswersSignInAgain() throws Exception {
        var builder = RestClient.builder();
        var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("http://domain/api/v1/auth/me")).andRespond(withStatus(HttpStatus.OK));
        var manager = mock(OAuth2AuthorizedClientManager.class);
        var session = new MockHttpSession();
        // The person signs out in another tab while this request's check is on its way.
        when(manager.authorize(any())).thenAnswer(call -> { session.invalidate(); return signedIn(); });
        SecurityContextHolder.getContext().setAuthentication(
                new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
        var request = new MockHttpServletRequest("GET", "/bff/api/v1/plans"); request.setSession(session);
        var response = new MockHttpServletResponse(); var reached = new AtomicBoolean();
        var lines = capture(() -> new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(OAUTH, builder.build()), OAUTH).doFilter(request, response, (req, res) -> reached.set(true)));
        assertThat(reached.get()).isFalse();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentAsString()).contains("AUTHENTICATION_REQUIRED");
        assertThat(lines).extracting(ILoggingEvent::getFormattedMessage).containsExactly(
                "Sign-in check failed for GET /bff/api/v1/plans: SESSION_ENDED, the session ended while the sign-in was being checked; the learner sign-in ends");
    }

    /**
     * DLV-1015: the filter reads the session's sign-in proof and hands it to SignInDomainClient (the client no longer reads
     * the session). In the cloud the proof of this session travels with the check; locally the proof is not read at all.
     */
    @Test
    void theSessionsProofTravelsWithTheCheckInTheCloudAndIsNotReadLocally() throws Exception {
        var cloud = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
        for (var oauth : List.of(cloud, OAUTH)) {
            var builder = RestClient.builder();
            var server = MockRestServiceServer.bindTo(builder).build();
            var manager = mock(OAuth2AuthorizedClientManager.class);
            when(manager.authorize(any())).thenReturn(signedIn());
            SecurityContextHolder.getContext().setAuthentication(
                    new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead"));
            var read = new ArrayList<String>();
            var session = new MockHttpSession() {
                @Override public Object getAttribute(String name) { read.add(name); return super.getAttribute(name); }
            };
            var request = new MockHttpServletRequest("POST", "/bff/api/v1/plans"); request.setSession(session);
            request.addHeader("X-LookAhead-SignIn-Proof", "attacker");
            String proof = SignInProofSession.proof(request, true);
            read.clear();
            var expected = server.expect(requestTo(oauth.domainApiUpstream() + "/api/v1/auth/me")).andExpect(header("Authorization", "Bearer server-only-token"));
            (oauth.cloud() ? expected.andExpect(header("X-LookAhead-SignIn-Proof", proof)) : expected.andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof")))
                    .andRespond(withStatus(HttpStatus.OK));
            var reached = new AtomicBoolean();
            new SignInCheckFilter(new SignInTokenClient(manager), new SignInDomainClient(oauth, builder.build()), oauth).doFilter(request, new MockHttpServletResponse(), (req, res) -> reached.set(true));
            assertThat(reached.get()).isTrue();
            server.verify();
            assertThat(read.contains(SignInProofSession.PROOF)).as("proof read, cloud=" + oauth.cloud()).isEqualTo(oauth.cloud());
            assertThat(session.isInvalid()).isFalse();
        }
    }

    /** DLV-969: the password pages are outside the sign-in check; the tear-down of this class clears the security context for this case too, as before. */
    @Nested class PasswordSignIn {
    final OAuthClientDetails oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    @Test void anEarlierPendingSignInChallengeDoesNotBlockANewPasswordSignIn() {
        var filter = new SignInCheckFilter(null, null, oauth);
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/sign-in");
        request.getSession().setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
        assertThat(filter.shouldNotFilter(request)).isTrue();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", "/bff/api/v1/plans"))).isFalse();
    }
    }
}
