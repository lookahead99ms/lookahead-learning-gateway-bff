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
    @ExceptionHandler(OAuth2AuthorizationException.class)
    ResponseEntity<?> expired(OAuth2AuthorizationException error) {
        return ResponseEntity.status(401).header("Cache-Control","no-store").body(Map.of("code","SESSION_EXPIRED","message","Sign in again to continue."));
    }
    @ExceptionHandler(RestClientException.class)
    ResponseEntity<?> unavailable(RestClientException error) {
        return ResponseEntity.status(503).header("Cache-Control","no-store").body(Map.of("code","SERVICE_UNAVAILABLE","message","The account service is temporarily unavailable. Retry shortly."));
    }
}
