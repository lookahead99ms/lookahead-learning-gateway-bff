package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import java.time.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/** Opens the DEV gate from a completed Look Ahead sign-in (DLV-969); never grants learner authentication or roles. */
@FunctionalInterface
public interface DevGate {
    void admit(HttpServletRequest request, OidcUser user);

    /** Admits only a sign-in whose ID token {@code auth_time} is fresh: at most 120 s old and at most 30 s ahead of the clock. */
    static DevGate freshSignIn(Clock clock) {
        return (request, user) -> {
            Instant now = clock.instant(), authTime = user.getIdToken().getAuthenticatedAt();
            if (authTime == null || authTime.isBefore(now.minusSeconds(120)) || authTime.isAfter(now.plusSeconds(30))) {
                SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_DENIED); throw new IllegalStateException("Stale sign-in");
            }
            String username = user.getClaimAsString("cognito:username");
            DevAdmission.grant(request, username == null ? user.getSubject() : username, user.getSubject(), now);
            SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_GRANTED);
        };
    }
}
