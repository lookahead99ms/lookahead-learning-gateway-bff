package com.lookahead.gateway.controller;

import com.lookahead.gateway.security.handler.PasswordSignInHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * DLV-969: the routes of our own sign-in and sign-up pages; what each one does is in {@code PasswordSignInHandler}.
 * CSRF-protected like every BFF POST.
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
@RequestMapping("/bff/api/v1/auth/password")
public class PasswordSignInController {
    private final PasswordSignInHandler handler;

    public PasswordSignInController(PasswordSignInHandler handler) { this.handler = handler; }

    @PostMapping("/sign-in")
    public ResponseEntity<?> signIn(HttpServletRequest request, HttpServletResponse response) { return handler.signIn(request, response); }

    @PostMapping("/challenge")
    public ResponseEntity<?> challenge(HttpServletRequest request, HttpServletResponse response) { return handler.challenge(request, response); }

    @PostMapping("/sign-up")
    public ResponseEntity<?> signUp(HttpServletRequest request) { return handler.signUp(request); }

    @PostMapping("/sign-up/confirm")
    public ResponseEntity<?> confirm(HttpServletRequest request) { return handler.confirm(request); }

    @PostMapping("/sign-up/resend")
    public ResponseEntity<?> resend(HttpServletRequest request) { return handler.resend(request); }

    @PostMapping("/password/forgot")
    public ResponseEntity<?> forgot(HttpServletRequest request) { return handler.forgot(request); }

    @PostMapping("/password/reset")
    public ResponseEntity<?> reset(HttpServletRequest request, HttpServletResponse response) { return handler.reset(request, response); }
}
