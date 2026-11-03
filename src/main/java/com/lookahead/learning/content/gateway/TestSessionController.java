package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

/**
 * DLV-969 S35: staff use DEV test accounts inside the DEV gate. After Sign out (the gate stays open), the sign-in page
 * lists the test accounts the gate holder may use; choosing one makes this Gateway session a test session.
 *
 * <p>The Domain decides on every call. The proxy sends the Gateway secret, the gate holder's {@code sub} (taken from
 * this session's gate admission, never from the browser) and the test account, and no bearer token. Test accounts
 * have no Cognito user and no password, so nothing here can open the gate.
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev'")
public class TestSessionController {
    static final String SECRET_HEADER = "X-LookAhead-Gateway-Secret", HOLDER_HEADER = "X-LookAhead-Gate-Subject",
            ACCOUNT_HEADER = "X-LookAhead-Test-Account";
    static final int RESPONSE_LIMIT = 256 * 1024;

    /** This Gateway session's sign-in while a test account is in use; the principal is the test account id. */
    static final class TestSession extends AbstractAuthenticationToken {
        private final String accountId;
        TestSession(String accountId) { super(List.of()); this.accountId = accountId; setAuthenticated(true); }
        @Override public Object getCredentials() { return null; }
        @Override public Object getPrincipal() { return accountId; }
    }
    record Start(String accountId) {}

    private final OAuthSettings settings;
    private final RestClient http;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();

    public TestSessionController(OAuthSettings settings, RestClient http) { this.settings = settings; this.http = http; }

    static boolean active(Authentication authentication) { return authentication instanceof TestSession; }

    /** Who opened this browser's DEV gate (their Cognito {@code sub}), while the gate is open; null otherwise. */
    static String holder(HttpServletRequest request) {
        return DevAdmission.current(request) instanceof DevAdmission.State state && DevAdmission.open(state, Instant.now()) ? state.subject() : null;
    }

    /** The proxy's headers for a test session; false (send nothing) when it is not one or the gate admission is gone. */
    static boolean apply(OAuthSettings settings, HttpServletRequest request, Authentication authentication, HttpHeaders headers) {
        String holder = holder(request);
        if (holder == null || !(authentication instanceof TestSession session)) return false;
        headers.set(SECRET_HEADER, settings.gatewaySecret());
        headers.set(HOLDER_HEADER, holder);
        headers.set(ACCOUNT_HEADER, session.accountId);
        return true;
    }

    /** The test accounts this gate holder may use. Empty while signed in as yourself: sign out first. */
    @GetMapping("/bff/api/v1/auth/test-accounts")
    public ResponseEntity<byte[]> accounts(HttpServletRequest request, Authentication authentication) {
        String holder = holder(request);
        if (holder == null || authentication instanceof OAuth2AuthenticationToken)
            return json(200, "{\"data\":[]}".getBytes(StandardCharsets.UTF_8));
        return relay(() -> http.get().uri(settings.domainApiUpstream() + "/internal/v1/test-sessions/accounts")
                .headers(headers -> domain(headers, holder)));
    }

    /** Starts (or switches) the test session once the Domain approves it; the browser then loads the platform. */
    @PostMapping("/bff/api/v1/auth/test-session")
    public ResponseEntity<byte[]> start(@RequestBody(required = false) Start body, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        String holder = holder(request);
        if (holder == null) return failure(401, "DEV_ADMISSION_REQUIRED", "Open DEV first.");
        if (authentication instanceof OAuth2AuthenticationToken) return failure(409, "SIGNED_IN", "Sign out before you use a test account.");
        UUID account;
        try { account = UUID.fromString(body.accountId()); }
        catch (RuntimeException invalid) { return failure(422, "TEST_ACCOUNT_REQUIRED", "Choose a test account."); }
        var answer = relay(() -> http.post().uri(settings.domainApiUpstream() + "/internal/v1/test-sessions/start")
                .headers(headers -> domain(headers, holder)).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("accountId", account.toString())));
        if (answer.getStatusCode().value() != 200) return answer;
        // Who this session is changes, so its id rotates, as at sign-in; the gate admission stays in the session.
        request.changeSessionId();
        var context = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        context.setAuthentication(new TestSession(account.toString()));
        SecurityContextHolder.getContextHolderStrategy().setContext(context);
        contexts.saveContext(context, request, response);
        return json(200, "{\"data\":{\"next\":\"/\"}}".getBytes(StandardCharsets.UTF_8));
    }

    private void domain(HttpHeaders headers, String holder) {
        headers.set(SECRET_HEADER, settings.gatewaySecret());
        headers.set(HOLDER_HEADER, holder);
    }

    private ResponseEntity<byte[]> relay(java.util.function.Supplier<RestClient.RequestHeadersSpec<?>> call) {
        try {
            return call.get().exchange((sent, received) -> {
                byte[] bytes = received.getBody().readNBytes(RESPONSE_LIMIT + 1);
                if (bytes.length > RESPONSE_LIMIT) return failure(502, "SERVICE_UNAVAILABLE", "Test accounts are unavailable. Retry shortly.");
                int status = received.getStatusCode().value();
                return json(status >= 500 ? 503 : status, bytes);
            });
        } catch (RuntimeException unavailable) {
            return failure(503, "SERVICE_UNAVAILABLE", "Test accounts are unavailable. Retry shortly.");
        }
    }

    static ResponseEntity<byte[]> failure(int status, String code, String message) {
        return json(status, ("{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    private static ResponseEntity<byte[]> json(int status, byte[] body) {
        return ResponseEntity.status(status).header(HttpHeaders.CACHE_CONTROL, "no-store").contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
