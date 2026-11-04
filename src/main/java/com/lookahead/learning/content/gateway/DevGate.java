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
                SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_DENIED);
                // DLV-969: why, with the sign-in's age in seconds; never who.
                String reason = authTime == null ? "MISSING_AUTH_TIME" : authTime.isAfter(now) ? "SIGN_IN_TIME_AHEAD" : "STALE_SIGN_IN";
                var line = OpsLog.refused("dev-gate.admitted", reason);
                if (authTime != null) line = line.addKeyValue("signIn.ageSeconds", Duration.between(authTime, now).toSeconds());
                line.log("DEV gate refused: {} (the gate opens only for a sign-in made in the last 120 s)", reason);
                throw new IllegalStateException("Stale sign-in");
            }
            String username = user.getClaimAsString("cognito:username");
            DevAdmission.grant(request, username == null ? user.getSubject() : username, user.getSubject(), now);
            SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_GRANTED);
            OpsLog.success("dev-gate.admitted").addKeyValue("dev-gate.window", DevAdmission.WINDOW.toString())
                .log("DEV gate opened for a fresh sign-in: open for {} hours, rechecked every {} minutes",
                    DevAdmission.WINDOW.toHours(), DevAdmission.RECHECK.toMinutes());
        };
    }
}
