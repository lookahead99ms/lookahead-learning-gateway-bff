package com.lookahead.gateway.security.session;

import com.lookahead.gateway.log.OpsLog;
import jakarta.servlet.http.HttpServletRequest;
import java.time.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

/** Opens the DEV gate from a completed Look Ahead sign-in (DLV-969); never grants learner authentication or roles. */
@FunctionalInterface
public interface DevAccessGate {
    void admit(HttpServletRequest request, OidcUser user);

    /**
     * Admits only a sign-in whose ID token {@code auth_time} is fresh: at most 120 s old and at most 30 s ahead of the clock.
     * The gate exists in the DEV environment only: any other {@code app.deployment-environment} refuses the start.
     */
    static DevAccessGate freshSignIn(Clock clock, String deploymentEnvironment) {
        if (!"dev".equals(deploymentEnvironment)) throw new IllegalStateException("DEV profile only");
        return (request, user) -> {
            Instant now = clock.instant(), authTime = user.getIdToken().getAuthenticatedAt();
            if (authTime == null || authTime.isBefore(now.minusSeconds(120)) || authTime.isAfter(now.plusSeconds(30))) {
                OpsLog.audit(OpsLog.AuditEvent.ADMISSION_DENIED);
                // DLV-969: why, with the sign-in's age in seconds; never who.
                String reason = authTime == null ? "MISSING_AUTH_TIME" : authTime.isAfter(now) ? "SIGN_IN_TIME_AHEAD" : "STALE_SIGN_IN";
                var line = OpsLog.refused("dev-gate.admitted", reason);
                if (authTime != null) line = line.addKeyValue("signIn.ageSeconds", Duration.between(authTime, now).toSeconds());
                line.log("DEV gate refused: {} (the gate opens only for a sign-in made in the last 120 s)", reason);
                throw new IllegalStateException("Stale sign-in");
            }
            String username = user.getClaimAsString("cognito:username");
            DevAccessSession.grant(request, username == null ? user.getSubject() : username, user.getSubject(), now);
            OpsLog.audit(OpsLog.AuditEvent.ADMISSION_GRANTED);
            OpsLog.success("dev-gate.admitted").addKeyValue("dev-gate.window", DevAccessSession.WINDOW.toString())
                .log("DEV gate opened for a fresh sign-in: open for {} hours, rechecked every {} minutes",
                    DevAccessSession.WINDOW.toHours(), DevAccessSession.RECHECK.toMinutes());
        };
    }
}
