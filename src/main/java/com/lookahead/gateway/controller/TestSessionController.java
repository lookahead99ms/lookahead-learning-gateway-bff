package com.lookahead.gateway.controller;

import com.lookahead.gateway.dto.TestSessionStart;
import com.lookahead.gateway.security.handler.TestSessionHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * DLV-969 S35: the four DEV routes of the test session (staff use DEV test accounts inside the DEV gate). The controller
 * holds the routes only; what each of them does is in {@code TestSessionHandler}.
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev'")
public class TestSessionController {
    private final TestSessionHandler handler;

    public TestSessionController(TestSessionHandler handler) { this.handler = handler; }

    /** The test accounts this gate holder may use: signed out, signed in as yourself, or already using one. */
    @GetMapping("/bff/api/v1/auth/test-accounts")
    public ResponseEntity<byte[]> accounts(HttpServletRequest request) {
        return handler.accounts(request);
    }

    /** Whether this session is a test session, and whether Back to my account has a staff sign-in to return to. */
    @GetMapping("/bff/api/v1/auth/test-session")
    public ResponseEntity<byte[]> status(HttpServletRequest request, Authentication authentication) {
        return handler.status(request, authentication);
    }

    /** Starts (or switches) the test session once the Domain approves it; the browser then loads the platform. */
    @PostMapping("/bff/api/v1/auth/test-session")
    public ResponseEntity<byte[]> start(@RequestBody(required = false) TestSessionStart body, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        return handler.start(body, request, response, authentication);
    }

    /**
     * Back to my account: the staff sign-in this test session started from becomes this session's sign-in again. Without one
     * (the test session began from the sign-in page, before DLV-969 switching) the test session simply ends, as Sign out does.
     */
    @PostMapping("/bff/api/v1/auth/test-session/end")
    public ResponseEntity<byte[]> end(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        return handler.end(request, response, authentication);
    }
}
