package com.lookahead.gateway;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.function.Supplier;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 * DLV-969 (owner, 2026-11-04): a health check that is not UP says why in the log. The answers themselves carry no
 * details ({@code show-details: never}) and the request log skips {@code /actuator/}, so every health indicator (the
 * readiness state the container health check reads, liveness, disk space, SSL bundles, ...) is wrapped: when one
 * reports anything but UP, one {@code lookahead.lifecycle} line names it, its status, a reason code and words; again at
 * most once a minute while it stays so, and once at INFO when it is UP again. The checks run only when something asks
 * (the ECS probe every 15 s), so nothing is polled for the log's sake. Never the indicator's details beyond plain
 * numbers: Boot puts exception messages and certificate names there.
 */
@Component
public class HealthLog implements BeanPostProcessor, ApplicationContextAware {
    static final Duration REPEAT = Duration.ofMinutes(1);
    private Supplier<LifecycleLog.Phase> phase = () -> LifecycleLog.Phase.RUNNING;
    private Clock clock = Clock.systemUTC();

    @Override public void setApplicationContext(ApplicationContext context) throws BeansException {
        phase = () -> {
            var lifecycle = context.getBeanProvider(LifecycleLog.class).getIfAvailable();
            return lifecycle == null ? LifecycleLog.Phase.RUNNING : lifecycle.phase();
        };
    }

    HealthLog with(Supplier<LifecycleLog.Phase> phase, Clock clock) { this.phase = phase; this.clock = clock; return this; }

    @Override public Object postProcessAfterInitialization(Object bean, String beanName) {
        return bean instanceof HealthIndicator indicator && !(bean instanceof Logged) ? new Logged(name(beanName), indicator, this) : bean;
    }

    /** The contributor name Boot derives from the bean name: {@code readinessStateHealthIndicator} is {@code readinessState}. */
    static String name(String beanName) {
        for (String suffix : new String[]{"HealthIndicator", "HealthContributor"})
            if (beanName.length() > suffix.length() && beanName.endsWith(suffix)) return beanName.substring(0, beanName.length() - suffix.length());
        return beanName;
    }

    record Why(String reason, String words, boolean expected) { }

    /** The reason code and words for an indicator that is not UP. {@code expected}: starting or stopping, logged at INFO. */
    Why why(String name, Health health) {
        String status = health.getStatus().getCode();
        switch (name) {
            case "readinessState" -> {
                return switch (phase.get()) {
                    case STARTING -> new Why("STARTING", "the Gateway has not finished starting; readiness turns UP once startup completes", true);
                    case STOPPING -> new Why("SHUTTING_DOWN", "the Gateway is shutting down and refuses new traffic", true);
                    case RUNNING -> new Why("REFUSING_TRAFFIC", "the Gateway was marked REFUSING_TRAFFIC while running (see the Readiness "
                            + "line); the container health check fails until it accepts traffic again", false);
                };
            }
            case "livenessState" -> { return new Why("LIVENESS_BROKEN", "the application marked itself BROKEN (see the Liveness line)", false); }
            case "diskSpace" -> {
                Map<String, Object> details = health.getDetails();
                return new Why("DISK_SPACE_LOW", "free disk space " + number(details.get("free")) + " bytes is below the threshold "
                        + number(details.get("threshold")) + " bytes", false);
            }
            case "ssl" -> { return new Why("CERTIFICATE_NOT_VALID", "an SSL bundle holds a certificate that is not valid now (expired or not yet valid)", false); }
            default -> {
                String failure = failureType(health.getDetails().get("error"));
                return new Why("HEALTH_" + status, "the " + name + " health check reported " + status
                        + (failure == null ? "" : " after " + failure), false);
            }
        }
    }

    private static String number(Object value) { return value instanceof Number number ? number.toString() : "unknown"; }

    /** Boot's {@code error} detail is "{@code type: message}": the simple type only, never the message. */
    static String failureType(Object error) {
        if (!(error instanceof String text)) return null;
        String type = text.contains(":") ? text.substring(0, text.indexOf(':')) : text;
        return type.matches("[A-Za-z_$][A-Za-z0-9_$.]{0,200}") ? type.substring(type.lastIndexOf('.') + 1) : null;
    }

    /** One indicator, unchanged in what it answers; only its result is looked at. */
    static final class Logged implements HealthIndicator {
        private final String name;
        private final HealthIndicator delegate;
        private final HealthLog log;
        private Status last;
        private Instant since, logged;

        Logged(String name, HealthIndicator delegate, HealthLog log) { this.name = name; this.delegate = delegate; this.log = log; }

        @Override public Health health() { return seen(delegate.health()); }

        @Override public Health health(boolean includeDetails) { return seen(delegate.health(includeDetails)); }

        HealthIndicator delegate() { return delegate; }

        private Health seen(Health health) {
            if (health != null) record(health);
            return health;
        }

        private synchronized void record(Health health) {
            Status status = health.getStatus();
            Instant now = log.clock.instant();
            if (Status.UP.equals(status)) {
                if (last != null && !Status.UP.equals(last))
                    StartupLog.LIFECYCLE.atInfo().addKeyValue("event.action", "health.check").addKeyValue("health.name", name)
                            .addKeyValue("health.status", "UP").addKeyValue("health.previous", last.getCode())
                            .addKeyValue("downSeconds", Duration.between(since, now).toSeconds())
                            .log("Health check {} is UP again after {} s ({} before)", name, Duration.between(since, now).toSeconds(), last.getCode());
                last = Status.UP; since = null; logged = null;
                return;
            }
            boolean changed = !status.equals(last);
            if (changed) since = now;
            if (changed || logged == null || !now.isBefore(logged.plus(REPEAT))) {
                Why why = log.why(name, health);
                (why.expected() ? StartupLog.LIFECYCLE.atInfo() : StartupLog.LIFECYCLE.atWarn())
                        .addKeyValue("event.action", "health.check").addKeyValue("health.name", name).addKeyValue("health.status", status.getCode())
                        .addKeyValue("reason", why.reason()).addKeyValue("downSeconds", Duration.between(since, now).toSeconds())
                        .log("Health check {} is {} ({}): {}{}", name, status.getCode(), why.reason(), why.words(),
                                changed ? "" : "; still so after " + Duration.between(since, now).toSeconds() + " s");
                logged = now;
            }
            last = status;
        }
    }
}
