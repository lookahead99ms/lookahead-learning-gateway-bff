package com.lookahead.gateway.security.handler;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.client.TestSessionDomainClient;
import com.lookahead.gateway.dto.TestSessionStart;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInSession;
import com.lookahead.gateway.security.session.TestSessionState;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * DLV-1015: what the four test-session routes do, driven directly on the handler over the real client and a controlled
 * Domain: who may ask, the account id, the browser's answer for each kind of Domain answer (moved here from
 * TestSessionDomainClientTest with the statements), the five log lines and the refusal line. The security chain in front of
 * the routes is in TestSessionControllerIntegrationTest; that each route is one call to these methods, in TestSessionControllerTest.
 */
class TestSessionHandlerTest {
    static final String LEARNER = "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a", SECOND = "7d1c0b9a-2e3f-4a5b-9c8d-1e2f3a4b5c6d";
    static final String UNAVAILABLE = "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Test accounts are unavailable. Retry shortly.\"}";
    final OAuthClientDetails oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    final RestClient.Builder builder = RestClient.builder();
    final MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
    final TestSessionHandler handler = new TestSessionHandler(new TestSessionDomainClient(oauth, builder.build()));
    final LogCapture log = new LogCapture("lookahead.event");
    final String accounts = oauth.domainApiUpstream() + "/internal/v1/test-sessions/accounts", start = oauth.domainApiUpstream() + "/internal/v1/test-sessions/start";

    @AfterEach void clear() { log.close(); SecurityContextHolder.clearContext(); }

    /** A request of a browser whose DEV gate is open: the admission is in its session, as DevAccessSession leaves it. */
    static MockHttpServletRequest gate() {
        var request = new MockHttpServletRequest();
        request.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("admin@example.test", "sub-admin", Instant.now()));
        return request;
    }
    static OAuth2AuthenticationToken staff() {
        return new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "synthetic-staff"), "sub"), Set.of(), "lookahead");
    }
    static String text(ResponseEntity<byte[]> answer) { return new String(answer.getBody(), StandardCharsets.UTF_8); }
    static Authentication signedIn(MockHttpServletRequest request) {
        return ((SecurityContext) request.getSession(false).getAttribute("SPRING_SECURITY_CONTEXT")).getAuthentication();
    }
    void approved() {
        server.expect(requestTo(start)).andExpect(method(HttpMethod.POST)).andExpect(header(TestSessionState.HOLDER_HEADER, "sub-admin"))
            .andRespond(withSuccess("{\"data\":{}}", MediaType.APPLICATION_JSON));
    }

    @Test void accountsAnswersWhatTheDomainAllowsThisGateHolderNeverStoredAndAsJson() {
        server.expect(requestTo(accounts)).andExpect(method(HttpMethod.GET))
            .andExpect(header(TestSessionState.SECRET_HEADER, oauth.domainSecret())).andExpect(header(TestSessionState.HOLDER_HEADER, "sub-admin"))
            .andRespond(withSuccess("{\"data\":[]}", MediaType.APPLICATION_JSON));
        var answer = handler.accounts(gate());
        server.verify();
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(answer.getBody(),StandardCharsets.UTF_8)).isEqualTo("{\"data\":[]}");
        assertThat(answer.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(answer.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        // The Domain's own refusal goes back with its status and body.
        server.reset();
        server.expect(requestTo(accounts)).andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON).body("{\"code\":\"TEST_ACCOUNT_FORBIDDEN\"}"));
        var refused = handler.accounts(gate());
        assertThat(refused.getStatusCode().value()).isEqualTo(403);
        assertThat(text(refused)).isEqualTo("{\"code\":\"TEST_ACCOUNT_FORBIDDEN\"}");
        assertThat(refused.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(log.lines()).isEmpty();
    }

    @Test void withoutAnOpenGateTheListIsEmptyAndTheDomainIsNotAsked() {
        var none = handler.accounts(new MockHttpServletRequest());
        assertThat(none.getStatusCode().value()).isEqualTo(200);
        assertThat(text(none)).isEqualTo("{\"data\":[]}");
        assertThat(none.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(none.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        // A gate whose window has passed is not a gate holder either.
        var expired = new MockHttpServletRequest();
        expired.getSession().setAttribute(DevAccessSession.ATTRIBUTE, new DevAccessSession.State("admin@example.test", "sub-admin", Instant.now().minus(DevAccessSession.WINDOW).minusSeconds(1)));
        assertThat(text(handler.accounts(expired))).isEqualTo("{\"data\":[]}");
        server.verify();
        assertThat(log.lines()).isEmpty();
    }

    @Test void aDomainErrorOrAnOversizedAnswerBecomesUnavailable() {
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts")).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("{}"));
        assertThat(handler.accounts(gate()).getStatusCode().value()).isEqualTo(503);
        server.verify();server.reset();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts"))
            .andRespond(withSuccess("x".repeat(TestSessionDomainClient.RESPONSE_LIMIT+1),MediaType.APPLICATION_JSON));
        var large=handler.accounts(gate());
        assertThat(large.getStatusCode().value()).isEqualTo(502);
        assertThat(new String(large.getBody(),StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Test accounts are unavailable. Retry shortly.\"}");
        server.verify();server.reset();
        assertThat(log.lines()).isEmpty();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts")).andRespond(request->{throw new IOException("synthetic outage");});
        var down=handler.accounts(gate());
        assertThat(down.getStatusCode().value()).isEqualTo(503);
        // The answer and the one line of a call that could not be made: written here, where the 503 is decided.
        assertThat(text(down)).isEqualTo(UNAVAILABLE);
        assertThat(down.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(log.messages()).containsExactly("Test session request could not reach Domain: DOMAIN_UNAVAILABLE (ResourceAccessException < IOException); answered 503");
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.domain", "event.outcome=failure", "reason=DOMAIN_UNAVAILABLE", "exception.types=ResourceAccessException < IOException");
        // Every server error is one 503 with the Domain's body; exactly the limit is still an answer.
        for (int status : new int[]{500, 502, 503, 504}) {
            server.reset();
            server.expect(requestTo(accounts)).andRespond(withStatus(HttpStatus.valueOf(status)).body("{\"code\":\"DOMAIN_SAYS\"}"));
            var error = handler.accounts(gate());
            assertThat(error.getStatusCode().value()).as("Domain %s", status).isEqualTo(503);
            assertThat(text(error)).isEqualTo("{\"code\":\"DOMAIN_SAYS\"}");
        }
        server.reset();
        server.expect(requestTo(accounts)).andRespond(withSuccess("x".repeat(TestSessionDomainClient.RESPONSE_LIMIT), MediaType.APPLICATION_JSON));
        var full = handler.accounts(gate());
        assertThat(full.getStatusCode().value()).isEqualTo(200);
        assertThat(full.getBody()).hasSize(TestSessionDomainClient.RESPONSE_LIMIT);
    }

    @Test void statusSaysWhetherATestSessionIsActiveAndWhetherThereIsAStaffSignInToReturnTo() {
        var test = new TestSessionState.TestSession(LEARNER);
        var answer = handler.status(gate(), test);
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(text(answer)).isEqualTo("{\"data\":{\"active\":true,\"canReturn\":false}}");
        assertThat(answer.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(answer.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        var kept = gate();
        kept.getSession().setAttribute(TestSessionState.STAFF_SIGN_IN, staff());
        assertThat(text(handler.status(kept, test))).isEqualTo("{\"data\":{\"active\":true,\"canReturn\":true}}");
        // Not a test session: signed out, or signed in as yourself, even with a sign-in kept aside.
        assertThat(text(handler.status(kept, null))).isEqualTo("{\"data\":{\"active\":false,\"canReturn\":false}}");
        assertThat(text(handler.status(kept, staff()))).isEqualTo("{\"data\":{\"active\":false,\"canReturn\":false}}");
        // The gate gone: the session no longer counts as a test session.
        var gone = new MockHttpServletRequest();
        gone.getSession().setAttribute(TestSessionState.STAFF_SIGN_IN, staff());
        assertThat(text(handler.status(gone, test))).isEqualTo("{\"data\":{\"active\":false,\"canReturn\":false}}");
        server.verify();
    }

    @Test void startIsRefusedWithoutTheGateOrAValidAccountIdOrWhenTheDomainSaysNoAndEachRefusalIsOneLine() {
        var noGate = new MockHttpServletRequest();
        var closed = handler.start(new TestSessionStart(LEARNER), noGate, new MockHttpServletResponse(), null);
        assertThat(closed.getStatusCode().value()).isEqualTo(401);
        assertThat(text(closed)).isEqualTo("{\"code\":\"DEV_ADMISSION_REQUIRED\",\"message\":\"Open DEV first.\"}");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: DEV_ADMISSION_REQUIRED (the DEV gate is not open in this session, HTTP 401)");
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.start", "event.outcome=refused", "reason=DEV_ADMISSION_REQUIRED", "http.status=401");
        // No body, no id, or an id that is not a UUID: refused before the Domain is asked.
        for (TestSessionStart body : new TestSessionStart[]{null, new TestSessionStart(null), new TestSessionStart(""), new TestSessionStart("not-a-uuid"), new TestSessionStart(" " + LEARNER)}) {
            var request = gate();
            var invalid = handler.start(body, request, new MockHttpServletResponse(), null);
            assertThat(invalid.getStatusCode().value()).isEqualTo(422);
            assertThat(text(invalid)).isEqualTo("{\"code\":\"TEST_ACCOUNT_REQUIRED\",\"message\":\"Choose a test account.\"}");
            assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: TEST_ACCOUNT_REQUIRED (no valid test account id was sent, HTTP 422)");
            assertThat(request.getSession().getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        }
        server.verify();
        // The Domain's refusal goes back as it is, with its code in the line.
        server.expect(requestTo(start)).andExpect(content().json("{\"accountId\":\"" + LEARNER + "\"}"))
            .andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON).body("{\"code\":\"TEST_SESSION_FORBIDDEN\",\"message\":\"Your role cannot use this test account.\"}"));
        var request = gate();
        String before = request.getSession().getId();
        var forbidden = handler.start(new TestSessionStart(LEARNER), request, new MockHttpServletResponse(), null);
        assertThat(forbidden.getStatusCode().value()).isEqualTo(403);
        assertThat(text(forbidden)).isEqualTo("{\"code\":\"TEST_SESSION_FORBIDDEN\",\"message\":\"Your role cannot use this test account.\"}");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: TEST_SESSION_FORBIDDEN (Domain refused the switch, HTTP 403)");
        assertThat(request.getSession().getId()).isEqualTo(before);
        assertThat(request.getSession().getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        // Without a code in the body the line names the status; an answer that is not 200 is a refusal even when it is a success status.
        server.verify(); server.reset();
        server.expect(requestTo(start)).andRespond(withStatus(HttpStatus.NO_CONTENT));
        assertThat(handler.start(new TestSessionStart(LEARNER), gate(), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(204);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: HTTP_204 (Domain refused the switch, HTTP 204)");
        // A Domain server error: 503, and the line is a failure that says the service was unavailable.
        server.verify(); server.reset();
        server.expect(requestTo(start)).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("{}"));
        assertThat(handler.start(new TestSessionStart(LEARNER), gate(), new MockHttpServletResponse(), null).getStatusCode().value()).isEqualTo(503);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: HTTP_503 (the test-session service was unavailable, HTTP 503)");
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.start", "event.outcome=failure", "reason=HTTP_503", "http.status=503");
        // The Domain not reached: the line of the failed call, then the refusal line with the code of our own 503.
        server.verify(); server.reset(); log.clear();
        server.expect(requestTo(start)).andRespond(withException(new IOException("down")));
        var down = handler.start(new TestSessionStart(LEARNER), gate(), new MockHttpServletResponse(), null);
        assertThat(down.getStatusCode().value()).isEqualTo(503);
        assertThat(text(down)).isEqualTo(UNAVAILABLE);
        assertThat(log.messages()).containsExactly("Test session request could not reach Domain: DOMAIN_UNAVAILABLE (ResourceAccessException < IOException); answered 503",
            "Test session request refused: SERVICE_UNAVAILABLE (the test-session service was unavailable, HTTP 503)");
    }

    @Test void startMakesTheSessionATestSessionAndTheLineSaysWhereItStartedFrom() {
        // Signed out inside the open gate.
        approved();
        var request = gate();
        String before = request.getSession().getId();
        var answer = handler.start(new TestSessionStart(LEARNER), request, new MockHttpServletResponse(), null);
        server.verify(); server.reset();
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(text(answer)).isEqualTo("{\"data\":{\"next\":\"/\"}}");
        assertThat(answer.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(request.getSession().getId()).isNotEqualTo(before);
        assertThat(TestSessionState.active(signedIn(request))).isTrue();
        assertThat(signedIn(request).getPrincipal()).isEqualTo(LEARNER);
        assertThat(request.getSession().getAttribute(SignInSession.LAST_ACTIVITY)).isInstanceOf(Instant.class);
        assertThat(request.getSession().getAttribute(TestSessionState.STAFF_SIGN_IN)).isNull();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session started while signed out: now using test account " + LEARNER);
        assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.started", "event.outcome=success", "testAccount.id=" + LEARNER, "from=signed-out");
        // From your own sign-in: it is kept aside.
        approved();
        var own = gate();
        var staff = staff();
        handler.start(new TestSessionStart(LEARNER), own, new MockHttpServletResponse(), staff);
        server.verify(); server.reset();
        assertThat(own.getSession().getAttribute(TestSessionState.STAFF_SIGN_IN)).isSameAs(staff);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session started from the staff sign-in: now using test account " + LEARNER + " (the staff sign-in is kept for Back to my account)");
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.switched", "event.outcome=success", "testAccount.id=" + LEARNER, "from=own-sign-in");
        // From one test account to another: the sign-in kept aside stays, and the line names both accounts.
        approved();
        handler.start(new TestSessionStart(SECOND), own, new MockHttpServletResponse(), signedIn(own));
        server.verify();
        assertThat(signedIn(own).getPrincipal()).isEqualTo(SECOND);
        assertThat(own.getSession().getAttribute(TestSessionState.STAFF_SIGN_IN)).isSameAs(staff);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session switched from test account " + LEARNER + " to test account " + SECOND);
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.switched", "event.outcome=success", "testAccount.id=" + SECOND, "testAccount.previousId=" + LEARNER, "from=test-account");
        assertThat(log.messages()).hasSize(3);
        log.assertNothing("admin@example.test", "sub-admin", "synthetic-staff", oauth.domainSecret());
    }

    @Test void endPutsTheStaffSignInBackOrEndsTheTestSessionAndRefusesWhenNoneIsInUse() {
        // Not in a test session: nothing to end.
        for (Authentication other : new Authentication[]{null, staff()}) {
            var refused = handler.end(gate(), new MockHttpServletResponse(), other);
            assertThat(refused.getStatusCode().value()).isEqualTo(409);
            assertThat(text(refused)).isEqualTo("{\"code\":\"NO_TEST_SESSION\",\"message\":\"No test account is in use.\"}");
            assertThat(log.last().getFormattedMessage()).isEqualTo("Test session request refused: NO_TEST_SESSION (no test account is in use, HTTP 409)");
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.end", "event.outcome=refused", "reason=NO_TEST_SESSION", "http.status=409");
        }
        // Started while signed out: the test session ends, the gate admission is carried into a fresh session.
        approved();
        var request = gate();
        handler.start(new TestSessionStart(LEARNER), request, new MockHttpServletResponse(), null);
        var old = request.getSession(false);
        var ended = handler.end(request, new MockHttpServletResponse(), signedIn(request));
        assertThat(ended.getStatusCode().value()).isEqualTo(200);
        assertThat(text(ended)).isEqualTo("{\"data\":{\"next\":\"/sign-in\"}}");
        assertThat(ended.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(request.getSession(false)).isNotSameAs(old);
        assertThat(request.getSession(false).getAttribute("SPRING_SECURITY_CONTEXT")).isNull();
        assertThat(request.getSession(false).getAttribute(DevAccessSession.ATTRIBUTE)).isNotNull();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Test session ended: test account " + LEARNER + " signed out, no staff sign-in to return to; the DEV gate stays open");
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.ended", "event.outcome=success", "testAccount.id=" + LEARNER);
        // Started from your own sign-in: Back to my account puts it back, with a new session id and nothing kept aside.
        server.verify(); server.reset(); approved();
        var own = gate();
        var staff = staff();
        handler.start(new TestSessionStart(SECOND), own, new MockHttpServletResponse(), staff);
        String during = own.getSession().getId();
        var back = handler.end(own, new MockHttpServletResponse(), signedIn(own));
        assertThat(back.getStatusCode().value()).isEqualTo(200);
        assertThat(text(back)).isEqualTo("{\"data\":{\"next\":\"/\"}}");
        assertThat(own.getSession().getId()).isNotEqualTo(during);
        assertThat(signedIn(own)).isSameAs(staff);
        assertThat(own.getSession().getAttribute(TestSessionState.STAFF_SIGN_IN)).isNull();
        assertThat(own.getSession().getAttribute(DevAccessSession.ATTRIBUTE)).isNotNull();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Back to my account: left test account " + SECOND + " and restored the staff sign-in");
        assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=test-session.back", "event.outcome=success", "testAccount.id=" + SECOND);
        assertThat(log.lines().stream().map(line -> line.getLevel()).distinct().toList()).isEqualTo(List.of(Level.WARN, Level.INFO));
        server.verify();
    }
}
