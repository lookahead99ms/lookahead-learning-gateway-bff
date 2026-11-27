package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.client.TestSessionDomainClient;
import com.lookahead.gateway.dto.TestSessionStart;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.TestSessionAnswer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

/**
 * DLV-969 S35: staff use DEV test accounts inside the DEV gate. After Sign out (the gate stays open), the sign-in page
 * lists the test accounts the gate holder may use; choosing one makes this Gateway BFF session a test session.
 *
 * <p>DLV-969 (owner, 2026-11-04): staff switch from their own sign-in through the account menu. That sign-in is kept
 * aside in this session ({@link TestSessionState#STAFF_SIGN_IN}) and Back to my account puts it back; Sign out and Exit DEV end it too.
 *
 * <p>The Domain decides on every call. {@link TestSessionDomainClient} sends the Gateway BFF secret, the gate holder's {@code sub} (taken from
 * this session's gate admission, never from the browser) and the test account, and no bearer token. Test accounts
 * have no Cognito user and no password, so nothing here can open the gate.
 *
 * <p>The four routes are in {@code TestSessionController}; each of them is one call to its method here.
 */
public final class TestSessionHandler {
    private final TestSessionDomainClient domainClient;

    public TestSessionHandler(TestSessionDomainClient domainClient) { this.domainClient = domainClient; }

    /** The test accounts this gate holder may use: signed out, signed in as yourself, or already using one. */
    public ResponseEntity<byte[]> accounts(HttpServletRequest request) {
        String holder = TestSessionState.holder(request);
        if (holder == null)
            return TestSessionAnswer.json(200, "{\"data\":[]}".getBytes(StandardCharsets.UTF_8));
        return relay(() -> domainClient.accounts(holder));
    }

    /** Whether this session is a test session, and whether Back to my account has a staff sign-in to return to. */
    public ResponseEntity<byte[]> status(HttpServletRequest request, Authentication authentication) {
        boolean active = TestSessionState.active(authentication) && TestSessionState.holder(request) != null, canReturn = active && TestSessionState.staffSignIn(request) != null;
        return TestSessionAnswer.json(200, ("{\"data\":{\"active\":" + active + ",\"canReturn\":" + canReturn + "}}").getBytes(StandardCharsets.UTF_8));
    }

    /** Starts (or switches) the test session once the Domain approves it; the browser then loads the platform. */
    public ResponseEntity<byte[]> start(TestSessionStart body, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        String holder = TestSessionState.holder(request);
        if (holder == null) return refused("test-session.start", TestSessionAnswer.failure(401, "DEV_ADMISSION_REQUIRED", "Open DEV first."), "the DEV gate is not open in this session");
        UUID account;
        try { account = UUID.fromString(body.accountId()); }
        catch (RuntimeException invalid) { return refused("test-session.start", TestSessionAnswer.failure(422, "TEST_ACCOUNT_REQUIRED", "Choose a test account."), "no valid test account id was sent"); }
        var answer = relay(() -> domainClient.start(holder, account));
        if (answer.getStatusCode().value() != 200) return refused("test-session.start", answer, "Domain refused the switch");
        TestSessionState.start(request, response, authentication, account);
        // DLV-969: test account ids are UUIDs, never names; the staff sign-in is described, not identified.
        if (authentication instanceof TestSessionState.TestSession previous)
            OpsLog.success("test-session.switched").addKeyValue("testAccount.id", account.toString()).addKeyValue("testAccount.previousId", previous.accountId)
                .addKeyValue("from", "test-account").log("Test session switched from test account {} to test account {}", previous.accountId, account);
        else if (authentication instanceof OAuth2AuthenticationToken)
            OpsLog.success("test-session.switched").addKeyValue("testAccount.id", account.toString()).addKeyValue("from", "own-sign-in")
                .log("Test session started from the staff sign-in: now using test account {} (the staff sign-in is kept for Back to my account)", account);
        else
            OpsLog.success("test-session.started").addKeyValue("testAccount.id", account.toString()).addKeyValue("from", "signed-out")
                .log("Test session started while signed out: now using test account {}", account);
        return TestSessionAnswer.json(200, "{\"data\":{\"next\":\"/\"}}".getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Back to my account: the staff sign-in this test session started from becomes this session's sign-in again. Without one
     * (the test session began from the sign-in page, before DLV-969 switching) the test session simply ends, as Sign out does.
     */
    public ResponseEntity<byte[]> end(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (!TestSessionState.active(authentication)) return refused("test-session.end", TestSessionAnswer.failure(409, "NO_TEST_SESSION", "No test account is in use."), "no test account is in use");
        String using = ((TestSessionState.TestSession) authentication).accountId;
        var staff = TestSessionState.staffSignIn(request);
        if (staff == null) {
            DevAccessSession.clearLearner(request);
            OpsLog.success("test-session.ended").addKeyValue("testAccount.id", using)
                .log("Test session ended: test account {} signed out, no staff sign-in to return to; the DEV gate stays open", using);
            return TestSessionAnswer.json(200, "{\"data\":{\"next\":\"/sign-in\"}}".getBytes(StandardCharsets.UTF_8));
        }
        TestSessionState.end(request, response, staff);
        OpsLog.success("test-session.back").addKeyValue("testAccount.id", using)
            .log("Back to my account: left test account {} and restored the staff sign-in", using);
        return TestSessionAnswer.json(200, "{\"data\":{\"next\":\"/\"}}".getBytes(StandardCharsets.UTF_8));
    }

    /** Logs a refused test-session request with its code (ours or Domain's) at WARN, or a Domain outage as a failure. */
    private static ResponseEntity<byte[]> refused(String action, ResponseEntity<byte[]> answer, String why) {
        int status = answer.getStatusCode().value();
        String code = OpsLog.code(answer.getBody());
        if (code == null) code = "HTTP_" + status;
        (status >= 500 ? OpsLog.failed(action, code) : OpsLog.refused(action, code)).addKeyValue("http.status", status)
            .log("Test session request refused: {} ({}, HTTP {})", code, status >= 500 ? "the test-session service was unavailable" : why, status);
        return answer;
    }

    /**
     * Shapes what the Domain answered for the browser: an answer larger than the limit is a 502, a server error a 503, any
     * other answer goes back with its own status and body. A call that could not be made or read is logged here and is a 503.
     */
    private static ResponseEntity<byte[]> relay(Supplier<TestSessionDomainClient.Answer> call) {
        try {
            var received = call.get();
            byte[] bytes = received.body();
            if (bytes.length > TestSessionDomainClient.RESPONSE_LIMIT) return TestSessionAnswer.failure(502, "SERVICE_UNAVAILABLE", "Test accounts are unavailable. Retry shortly.");
            int status = received.status();
            return TestSessionAnswer.json(status >= 500 ? 503 : status, bytes);
        } catch (RuntimeException unavailable) {
            OpsLog.failed("test-session.domain", "DOMAIN_UNAVAILABLE").addKeyValue("exception.types", OpsLog.types(unavailable))
                .log("Test session request could not reach Domain: DOMAIN_UNAVAILABLE ({}); answered 503", OpsLog.types(unavailable));
            return TestSessionAnswer.failure(503, "SERVICE_UNAVAILABLE", "Test accounts are unavailable. Retry shortly.");
        }
    }
}
