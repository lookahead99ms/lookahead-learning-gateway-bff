package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;

/** DLV-969 (owner, 2026-11-04): every availability change, the startup summary and the stop each leave one line saying why. */
class LifecycleLogTest {
    static final String SECRET = "synthetic-upstream-password";
    final LogCapture log = new LogCapture("lookahead.lifecycle");
    final GenericApplicationContext context = new GenericApplicationContext();

    @AfterEach void close() { log.close(); }

    MockEnvironment environment() {
        var environment = new MockEnvironment()
                .withProperty("app.deployment-environment", "dev")
                .withProperty("app.oauth.domain-api-upstream", "https://gateway:" + SECRET + "@domain.lookahead-dev.internal:8443/x?token=" + SECRET)
                .withProperty("app.gateway.web-upstream", "https://web.lookahead-dev.internal:8443")
                .withProperty("app.oauth.identity-upstream", "not a uri " + SECRET)
                .withProperty("app.author-previews.enabled", "false")
                .withProperty("app.author-previews.upstream", "http://127.0.0.1:4315")
                .withProperty("app.cognito.issuer", "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_PoolSecret123")
                .withProperty("local.server.port", "8443").withProperty("local.management.port", "8081");
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        return environment;
    }

    LifecycleLog lifecycle(MockEnvironment environment, boolean build) {
        var beans = new DefaultListableBeanFactory();
        if (build) {
            var properties = new Properties();
            properties.setProperty("version", "2026.11.04.1");
            properties.setProperty("releaseTag", "v2026.11.04.20.00");
            properties.setProperty("sourceRevision", "abc1234");
            beans.registerSingleton("build", new BuildProperties(properties));
        }
        return new LifecycleLog(context, environment, beans.getBeanProvider(BuildProperties.class), () -> 93_400);
    }

    @Test void startupLogsLivenessReadinessAndOneSummaryWithServiceNamesOnly() {
        var lifecycle = lifecycle(environment(), true);
        assertThat(lifecycle.phase()).isEqualTo(LifecycleLog.Phase.STARTING);
        lifecycle.availability(new AvailabilityChangeEvent<>(context, LivenessState.CORRECT));
        lifecycle.availability(new AvailabilityChangeEvent<>(context, ReadinessState.ACCEPTING_TRAFFIC));
        lifecycle.availability(new AvailabilityChangeEvent<>(context, ReadinessState.ACCEPTING_TRAFFIC));  // no change: no line
        assertThat(lifecycle.phase()).isEqualTo(LifecycleLog.Phase.RUNNING);
        assertThat(log.messages()).containsExactly(
                "Liveness changed to CORRECT (was not reported): the application is running",
                "Readiness changed to ACCEPTING_TRAFFIC (was not reported): /actuator/health/readiness answers UP",
                "Started and ready: Gateway 2026.11.04.1 (release v2026.11.04.20.00, commit abc1234), profiles [gateway,lower-cost-dev], "
                        + "readiness ACCEPTING_TRAFFIC, port 8443, management port 8081, upstreams domain=domain.lookahead-dev.internal:8443 "
                        + "web=web.lookahead-dev.internal:8443 identity=unparseable cognito=us-east-2");
        assertThat(log.lines()).allMatch(line -> line.getLevel() == Level.INFO);
        assertThat(LogCapture.pairs(log.last())).contains("event.action=startup.ready", "gateway.version=2026.11.04.1",
                "release.tag=v2026.11.04.20.00", "release.revision=abc1234", "readiness.state=ACCEPTING_TRAFFIC", "liveness.state=CORRECT",
                "server.port=8443", "management.port=8081", "deployment.environment=dev");
        // Never a password, path, query or the Cognito pool id.
        log.assertNothing(SECRET, "/x", "token=", "PoolSecret123", "4315");
        // Refusing and accepting traffic again: logged, but the summary only once.
        lifecycle.availability(new AvailabilityChangeEvent<>(this, ReadinessState.REFUSING_TRAFFIC));
        lifecycle.availability(new AvailabilityChangeEvent<>(this, ReadinessState.ACCEPTING_TRAFFIC));
        assertThat(log.messages()).filteredOn(message -> message.startsWith("Started")).hasSize(1);
    }

    @Test void refusingTrafficWhileRunningAndABrokenLivenessAreWarnings() {
        var lifecycle = lifecycle(environment(), true);
        lifecycle.availability(new AvailabilityChangeEvent<>(context, ReadinessState.ACCEPTING_TRAFFIC));
        log.clear();
        lifecycle.availability(new AvailabilityChangeEvent<>(this, ReadinessState.REFUSING_TRAFFIC));
        lifecycle.availability(new AvailabilityChangeEvent<>(this, LivenessState.BROKEN));
        assertThat(log.lines()).allMatch(line -> line.getLevel() == Level.WARN);
        assertThat(log.messages().get(0)).isEqualTo("Readiness changed to REFUSING_TRAFFIC (was ACCEPTING_TRAFFIC): marked by LifecycleLogTest "
                + "while running; /actuator/health/readiness answers 503 OUT_OF_SERVICE and the container health check fails until it is accepting traffic again");
        assertThat(LogCapture.pairs(log.lines().get(0))).contains("reason=MARKED_REFUSING_TRAFFIC", "readiness.previous=ACCEPTING_TRAFFIC");
        assertThat(log.messages().get(1)).isEqualTo("Liveness changed to BROKEN (was not reported): marked by LifecycleLogTest; /actuator/health/liveness answers 503");
        assertThat(LogCapture.pairs(log.lines().get(1))).contains("reason=LIVENESS_BROKEN");
        assertThat(lifecycle.phase()).isEqualTo(LifecycleLog.Phase.RUNNING);
    }

    @Test void shutdownSaysItWasRequestedWithUptimeAndTheReadinessBeforeIt() {
        var lifecycle = lifecycle(environment(), true);
        lifecycle.availability(new AvailabilityChangeEvent<>(context, ReadinessState.ACCEPTING_TRAFFIC));
        log.clear();
        // Spring Boot refuses traffic first thing when the context closes, then publishes ContextClosedEvent.
        lifecycle.availability(new AvailabilityChangeEvent<>(context, ReadinessState.REFUSING_TRAFFIC));
        assertThat(lifecycle.phase()).isEqualTo(LifecycleLog.Phase.STOPPING);
        lifecycle.closed(new ContextClosedEvent(new GenericApplicationContext()));  // the management child context: ignored
        lifecycle.closed(new ContextClosedEvent(context));
        assertThat(log.lines()).allMatch(line -> line.getLevel() == Level.INFO).hasSize(2);
        assertThat(LogCapture.pairs(log.lines().get(0))).contains("reason=SHUTTING_DOWN");
        assertThat(log.last().getFormattedMessage()).isEqualTo(LifecycleLog.STOPPING + "; uptime 93 s, readiness until now ACCEPTING_TRAFFIC");
        assertThat(log.last().getFormattedMessage()).startsWith("Stopping: shutdown requested (SIGTERM from the platform, e.g. ECS stop or failed health check)");
        assertThat(LogCapture.pairs(log.last())).contains("event.action=shutdown.requested", "uptimeSeconds=93", "readiness.last=ACCEPTING_TRAFFIC", "ready.reached=true");
    }

    @Test void aStopBeforeEverBeingReadySaysSo() {
        var environment = new MockEnvironment().withProperty("app.oauth.domain-api-upstream", "${UNRESOLVED_PLACEHOLDER}");
        var lifecycle = lifecycle(environment, false);
        lifecycle.closed(new ContextClosedEvent(context));
        assertThat(log.last().getFormattedMessage()).isEqualTo(LifecycleLog.STOPPING_UNREADY + "; uptime 93 s, readiness until now not reported");
        assertThat(LogCapture.pairs(log.last())).contains("readiness.last=NONE", "ready.reached=false");
        // Without build information or upstreams the summary still renders.
        lifecycle.summary();
        assertThat(log.last().getFormattedMessage()).contains("Gateway unknown (release unknown, commit unknown)", "port unset",
                "management port same as server", "upstreams none");
        assertThat(lifecycle.upstreams()).isEqualTo("none");
    }

    @Test void upstreamsListAuthorPreviewsOnlyWhenEnabledAndCognitoByRegion() {
        var environment = environment().withProperty("app.author-previews.enabled", "true")
                .withProperty("app.cognito.issuer", "https://login.example.test/pool");
        assertThat(lifecycle(environment, true).upstreams()).endsWith("author-previews=127.0.0.1:4315 cognito=configured");
        assertThat(LifecycleLog.host("https://domain.lookahead-dev.internal", true)).isEqualTo("domain.lookahead-dev.internal");
        assertThat(LifecycleLog.host("mailto:x", true)).isNull();
    }
}
