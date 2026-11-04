package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.env.MockEnvironment;

/** DLV-969 (owner, 2026-11-04): a health check that is not UP says why, on change and once a minute; UP again once. */
class HealthLogTest {
    static final String SECRET = "synthetic-secret-in-an-exception-message";
    final LogCapture log = new LogCapture("lookahead.lifecycle");
    final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-11-04T20:00:00Z"));
    final AtomicReference<LifecycleLog.Phase> phase = new AtomicReference<>(LifecycleLog.Phase.RUNNING);
    final Clock clock = new Clock() {
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now.get(); }
    };
    final HealthLog health = new HealthLog().with(phase::get, clock);
    final AtomicReference<Health> answer = new AtomicReference<>(Health.up().build());

    @AfterEach void close() { log.close(); }

    HealthIndicator wrapped(String beanName) {
        HealthIndicator indicator = answer::get;
        return (HealthIndicator) health.postProcessAfterInitialization(indicator, beanName);
    }

    void advance(long seconds) { now.set(now.get().plusSeconds(seconds)); }

    @Test void readinessDownIsLoggedOnChangeThenOnceAMinuteAndUpOnceOnRecovery() {
        var readiness = wrapped("readinessStateHealthIndicator");
        assertThat(readiness.health()).isEqualTo(Health.up().build());
        assertThat(log.lines()).isEmpty();  // UP from the start: nothing to say
        answer.set(Health.outOfService().build());
        assertThat(readiness.health(false).getStatus()).isEqualTo(Status.OUT_OF_SERVICE);  // the answer is unchanged
        advance(15); readiness.health(false);
        advance(15); readiness.health(false);
        assertThat(log.lines()).hasSize(1);
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Health check readinessState is OUT_OF_SERVICE (REFUSING_TRAFFIC): the Gateway was "
                + "marked REFUSING_TRAFFIC while running (see the Readiness line); the container health check fails until it accepts traffic again");
        assertThat(LogCapture.pairs(log.last())).contains("event.action=health.check", "health.name=readinessState", "health.status=OUT_OF_SERVICE",
                "reason=REFUSING_TRAFFIC", "downSeconds=0");
        advance(30); readiness.health(false);
        assertThat(log.lines()).hasSize(2);
        assertThat(log.last().getFormattedMessage()).endsWith("; still so after 60 s");
        advance(20); answer.set(Health.up().build()); readiness.health(false); readiness.health(false);
        assertThat(log.lines()).hasSize(3);
        assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
        assertThat(log.last().getFormattedMessage()).isEqualTo("Health check readinessState is UP again after 80 s (OUT_OF_SERVICE before)");
        // A new failure logs at once, not a minute after the last line.
        answer.set(Health.outOfService().build()); readiness.health();
        assertThat(log.lines()).hasSize(4);
        log.assertNothing();
    }

    @Test void startingAndStoppingAreExplainedAtInfo() {
        var readiness = wrapped("readinessStateHealthIndicator");
        answer.set(Health.outOfService().build());
        phase.set(LifecycleLog.Phase.STARTING); readiness.health();
        assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
        assertThat(LogCapture.pairs(log.last())).contains("reason=STARTING");
        assertThat(log.last().getFormattedMessage()).contains("has not finished starting");
        phase.set(LifecycleLog.Phase.STOPPING); advance(60); readiness.health();
        assertThat(LogCapture.pairs(log.last())).contains("reason=SHUTTING_DOWN");
    }

    @Test void eachIndicatorSaysWhyInItsOwnTermsAndNeverCopiesMessages() {
        answer.set(Health.down().withDetail("free", 1024L).withDetail("threshold", 10_485_760L).withDetail("path", "/" + SECRET).build());
        wrapped("diskSpaceHealthIndicator").health();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Health check diskSpace is DOWN (DISK_SPACE_LOW): free disk space 1024 bytes is "
                + "below the threshold 10485760 bytes");
        answer.set(Health.down().build());
        wrapped("livenessStateHealthIndicator").health();
        assertThat(LogCapture.pairs(log.last())).contains("reason=LIVENESS_BROKEN");
        answer.set(Health.outOfService().withDetail("invalidChains", SECRET).build());
        wrapped("sslHealthIndicator").health();
        assertThat(LogCapture.pairs(log.last())).contains("reason=CERTIFICATE_NOT_VALID");
        answer.set(Health.down(new java.io.UncheckedIOException(new java.io.IOException(SECRET))).build());
        wrapped("customHealthContributor").health();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Health check custom is DOWN (HEALTH_DOWN): the custom health check reported DOWN "
                + "after UncheckedIOException");
        answer.set(Health.status("DEGRADED").withDetail("error", "not a type: " + SECRET).build());
        wrapped("other").health();
        assertThat(log.last().getFormattedMessage()).isEqualTo("Health check other is DEGRADED (HEALTH_DEGRADED): the other health check reported DEGRADED");
        assertThat(log.lines()).hasSize(5).allMatch(line -> line.getLevel() == Level.WARN);
        log.assertNothing(SECRET);
        assertThat(HealthLog.failureType(42)).isNull();
    }

    @Test void onlyHealthIndicatorsAreWrappedOnceAndKeepTheirAnswers() {
        Object other = new Object();
        assertThat(health.postProcessAfterInitialization(other, "plain")).isSameAs(other);
        var once = (HealthLog.Logged) wrapped("pingHealthIndicator");
        assertThat(health.postProcessAfterInitialization(once, "pingHealthIndicator")).isSameAs(once);
        assertThat(once.delegate().health()).isEqualTo(Health.up().build());
        assertThat(HealthLog.name("readinessStateHealthIndicator")).isEqualTo("readinessState");
        assertThat(HealthLog.name("HealthIndicator")).isEqualTo("HealthIndicator");
        HealthIndicator nothing = () -> null;
        assertThat(((HealthIndicator) health.postProcessAfterInitialization(nothing, "x")).health()).isNull();
    }

    /** In a context the decorator wraps the health beans and asks the lifecycle for the phase. */
    @Test void inAContextTheHealthBeansAreWrappedAndThePhaseComesFromTheLifecycle() {
        new ApplicationContextRunner().withBean(HealthLog.class).withBean(MockEnvironment.class)
                .withBean("readinessStateHealthIndicator", HealthIndicator.class, () -> () -> Health.outOfService().build())
                .run(context -> {
                    assertThat(context.getBean("readinessStateHealthIndicator")).isInstanceOf(HealthLog.Logged.class);
                    context.getBean("readinessStateHealthIndicator", HealthIndicator.class).health();
                    assertThat(LogCapture.pairs(log.last())).contains("reason=REFUSING_TRAFFIC");  // no lifecycle bean: running
                });
        log.clear();
        new ApplicationContextRunner().withBean(HealthLog.class).withBean(LifecycleLog.class)
                .withBean("readinessStateHealthIndicator", HealthIndicator.class, () -> () -> Health.outOfService().build())
                .run(context -> {
                    context.getBean("readinessStateHealthIndicator", HealthIndicator.class).health();
                    assertThat(LogCapture.pairs(log.last())).contains("reason=STARTING");
                });
    }
}
