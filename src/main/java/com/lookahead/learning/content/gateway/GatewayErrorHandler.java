package com.lookahead.learning.content.gateway;

import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClientException;
import java.util.Map;

@RestControllerAdvice(assignableTypes={GatewayController.class, IdentityProxyController.class, AccountProxyController.class})
@Profile("gateway")
@Order(-100)
public class GatewayErrorHandler {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GatewayErrorHandler.class);
    @ExceptionHandler(OAuth2AuthorizationException.class)
    ResponseEntity<?> expired(OAuth2AuthorizationException error) {
        return ResponseEntity.status(401).header("Cache-Control","no-store").body(Map.of("code","SESSION_EXPIRED","message","Sign in again to continue."));
    }
    /** DLV-969: the caller sees only "unavailable" (the request ID is in its X-Request-Id header); the log keeps which call
     *  failed and the exception types, never their messages, which can carry a token or an upstream body. */
    @ExceptionHandler(RestClientException.class)
    ResponseEntity<?> unavailable(RestClientException error, jakarta.servlet.http.HttpServletRequest request) {
        log.warn("Upstream unavailable reference={} {} {}: {}", RequestLog.reference(), RequestLog.method(request), RequestLog.path(request), RequestLog.types(error));
        return ResponseEntity.status(503).header("Cache-Control","no-store").body(Map.of("code","SERVICE_UNAVAILABLE","message","The account service is temporarily unavailable. Retry shortly."));
    }
}
