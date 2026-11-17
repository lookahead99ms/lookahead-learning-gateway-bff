package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;

/**
 * Plain logs (owner decision 2026-11-17): the one console pattern in application.yml renders every lifecycle line as
 * "{@code <UTC timestamp with millis> <LEVEL padded to 5> <sentence>}", with no logger, thread, PID, service name or keys,
 * no request bracket outside a request, and no trailing spaces. Rendered here through the real pattern, at a fixed instant.
 */
class PlainLogLineTest {
    static final Instant AT = Instant.parse("2026-11-17T20:41:18.144Z");

    @Test void everyLifecycleLineIsOnePlainSentence() {
        var environment = new MockEnvironment().withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443")
                .withProperty("app.deployment-environment", "dev").withProperty("local.server.port", "8443");
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        var beans = new DefaultListableBeanFactory();
        var properties = new Properties(); properties.setProperty("version", "1.2.3");
        beans.registerSingleton("build", new BuildProperties(properties));
        try (var log = new LogCapture("lookahead.lifecycle"); var application = new GenericApplicationContext()) {
            var lifecycle = new LifecycleLog(application, environment, beans.getBeanProvider(BuildProperties.class), () -> 5000);
            lifecycle.availability(new AvailabilityChangeEvent<>(application, ReadinessState.ACCEPTING_TRAFFIC));
            HealthIndicator down = () -> Health.down().build();
            ((HealthIndicator) new HealthLog().postProcessAfterInitialization(down, "livenessStateHealthIndicator")).health();
            try { StartupLog.refused("app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER)", "MISSING", "fixed message"); } catch (RuntimeException ignored) { }
            lifecycle.closed(new ContextClosedEvent(application));
            var lines = log.lines().stream().map(line -> LogCapture.plain(line, AT)).toList();
            assertThat(lines).containsExactly(
                    "2026-11-17T20:41:18.144Z INFO  Readiness changed to ACCEPTING_TRAFFIC (was not reported): ACCEPTING_TRAFFIC (/actuator/health/readiness answers UP)\n",
                    "2026-11-17T20:41:18.144Z INFO  Started and ready: Gateway 1.2.3 (release unknown, commit unknown), profiles [gateway,lower-cost-dev], environment dev, "
                            + "readiness ACCEPTING_TRAFFIC, liveness not reported, port 8443, management port same as server, upstreams domain=domain.lookahead-dev.internal:8443\n",
                    "2026-11-17T20:41:18.144Z WARN  Health check livenessState is DOWN (LIVENESS_BROKEN): the application marked itself BROKEN (see the Liveness line)\n",
                    "2026-11-17T20:41:18.144Z WARN  Startup refused: app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER) is missing or empty (MISSING): fixed message; the Gateway will not start\n",
                    "2026-11-17T20:41:18.144Z INFO  " + LifecycleLog.STOPPING + "; uptime 5 s, readiness until now ACCEPTING_TRAFFIC\n");
            for (String line : lines) assertThat(line).doesNotContain("ERROR", "[request", "lookahead.lifecycle", "event.action").doesNotEndWith(" \n");
            // The deploy's log scan still finds a refused start by its fixed phrase, on the same line as the level word.
            assertThat(lines.get(3)).contains("Startup refused:");
        }
    }

    @Test void theRequestBracketAppearsOnlyWhileARequestIdIsSetAndShowsItsFirstEightCharacters() {
        try (var log = new LogCapture("lookahead.lifecycle")) {
            MDC.put("requestId", "5e17c0aa-7b1d-4e2f-9a3b-6c5d4e3f2a1b");
            try {
                StartupLog.LIFECYCLE.info("Cognito GetUser succeeded in 21 ms");
            } finally {
                MDC.remove("requestId");
            }
            StartupLog.LIFECYCLE.warn("Free plan limit hit for account faaac829: at most 2 active free plans at once");
            assertThat(LogCapture.plain(log.lines().get(0), AT)).isEqualTo("2026-11-17T20:41:18.144Z INFO  Cognito GetUser succeeded in 21 ms  [request 5e17c0aa]\n");
            assertThat(LogCapture.plain(log.lines().get(1), AT)).isEqualTo("2026-11-17T20:41:18.144Z WARN  Free plan limit hit for account faaac829: at most 2 active free plans at once\n");
        }
    }
}
