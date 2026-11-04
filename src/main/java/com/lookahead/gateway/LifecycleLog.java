package com.lookahead.gateway;

import java.lang.management.ManagementFactory;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.LivenessState;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.info.BuildProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * DLV-969 (owner, 2026-11-04): the Gateway's start, its availability and its stop, each in one {@code lookahead.lifecycle}
 * line, so CloudWatch shows why a task stopped serving instead of only "started" and "stopped".
 * <ul>
 *   <li>Every Spring Boot availability change (readiness and liveness), once per change. Refusing traffic outside a
 *   shutdown and a broken liveness are WARN; everything else INFO.</li>
 *   <li>One summary once the Gateway first accepts traffic: version, release tag, commit, profiles, ports and which
 *   upstreams are configured (host names and ports only: never a path, query, user or password).</li>
 *   <li>One line when the context closes: shutdown requested, uptime and the readiness it had until then.</li>
 * </ul>
 */
@Component
public class LifecycleLog {
    static final Logger LIFECYCLE = StartupLog.LIFECYCLE;
    static final String STOPPING = "Stopping: shutdown requested (SIGTERM from the platform, e.g. ECS stop or failed health check)";
    static final String STOPPING_UNREADY = "Stopping before the Gateway ever became ready: shutdown requested (SIGTERM from the platform, "
            + "e.g. ECS stop or failed health check) or the start failed";

    /** Where the application is in its life: health lines word an unready readiness by it. */
    public enum Phase { STARTING, RUNNING, STOPPING }

    private final ApplicationContext context;
    private final Environment environment;
    private final ObjectProvider<BuildProperties> build;
    private final LongSupplier uptimeMillis;
    private final AtomicBoolean summarized = new AtomicBoolean();
    private volatile Phase phase = Phase.STARTING;
    private volatile ReadinessState readiness;
    private volatile ReadinessState readinessBeforeStop;
    private volatile LivenessState liveness;

    @org.springframework.beans.factory.annotation.Autowired
    public LifecycleLog(ApplicationContext context, Environment environment, ObjectProvider<BuildProperties> build) {
        this(context, environment, build, () -> ManagementFactory.getRuntimeMXBean().getUptime());
    }

    LifecycleLog(ApplicationContext context, Environment environment, ObjectProvider<BuildProperties> build, LongSupplier uptimeMillis) {
        this.context = context;
        this.environment = environment;
        this.build = build;
        this.uptimeMillis = uptimeMillis;
    }

    public Phase phase() { return phase; }

    @EventListener
    public void availability(AvailabilityChangeEvent<?> event) {
        if (event.getState() instanceof ReadinessState state) readiness(state, event.getSource());
        else if (event.getState() instanceof LivenessState state) liveness(state, event.getSource());
    }

    private synchronized void readiness(ReadinessState state, Object source) {
        if (state == readiness) return;
        ReadinessState previous = readiness;
        readiness = state;
        var line = LIFECYCLE.atInfo();
        String reason, words;
        if (state == ReadinessState.ACCEPTING_TRAFFIC) {
            phase = Phase.RUNNING;
            reason = "ACCEPTING_TRAFFIC";
            words = "/actuator/health/readiness answers UP";
        } else if (source instanceof ApplicationContext) {
            // Spring Boot itself refuses traffic first thing when the context closes (SIGTERM, ECS stop, failed health check).
            phase = Phase.STOPPING;
            readinessBeforeStop = previous;
            reason = "SHUTTING_DOWN";
            words = "the application context is closing; /actuator/health/readiness now answers 503 OUT_OF_SERVICE";
        } else {
            line = LIFECYCLE.atWarn();
            reason = "MARKED_REFUSING_TRAFFIC";
            words = "marked by " + type(source) + " while running; /actuator/health/readiness answers 503 OUT_OF_SERVICE and the "
                    + "container health check fails until it is accepting traffic again";
        }
        line.addKeyValue("event.action", "availability.readiness").addKeyValue("readiness.state", state.name())
                .addKeyValue("readiness.previous", previous == null ? "NONE" : previous.name()).addKeyValue("reason", reason)
                .log("Readiness changed to {} (was {}): {}", state, previous == null ? "not reported" : previous, words);
        if (state == ReadinessState.ACCEPTING_TRAFFIC && summarized.compareAndSet(false, true)) summary();
    }

    private synchronized void liveness(LivenessState state, Object source) {
        if (state == liveness) return;
        LivenessState previous = liveness;
        liveness = state;
        boolean broken = state == LivenessState.BROKEN;
        (broken ? LIFECYCLE.atWarn() : LIFECYCLE.atInfo()).addKeyValue("event.action", "availability.liveness")
                .addKeyValue("liveness.state", state.name()).addKeyValue("liveness.previous", previous == null ? "NONE" : previous.name())
                .addKeyValue("reason", broken ? "LIVENESS_BROKEN" : "LIVENESS_CORRECT")
                .log(broken ? "Liveness changed to BROKEN (was {}): marked by {}; /actuator/health/liveness answers 503"
                        : "Liveness changed to CORRECT (was {}): the application is running", previous == null ? "not reported" : previous, type(source));
    }

    /** The startup summary: what is running, where it listens and which upstreams it was given. */
    void summary() {
        var info = build.getIfAvailable();
        String version = info == null || info.getVersion() == null ? "unknown" : info.getVersion();
        String tag = info == null || info.get("releaseTag") == null ? "unknown" : info.get("releaseTag");
        String revision = info == null || info.get("sourceRevision") == null ? "unknown" : info.get("sourceRevision");
        String profiles = String.join(",", environment.getActiveProfiles());
        String port = property("local.server.port"), management = property("local.management.port");
        String upstreams = upstreams();
        LIFECYCLE.atInfo().addKeyValue("event.action", "startup.ready").addKeyValue("event.outcome", "success")
                .addKeyValue("gateway.version", version).addKeyValue("release.tag", tag).addKeyValue("release.revision", revision)
                .addKeyValue("profiles", profiles).addKeyValue("deployment.environment", value(property("app.deployment-environment")))
                .addKeyValue("readiness.state", String.valueOf(readiness)).addKeyValue("liveness.state", String.valueOf(liveness))
                .addKeyValue("server.port", value(port)).addKeyValue("management.port", value(management)).addKeyValue("upstreams", upstreams)
                .log("Started and ready: Gateway {} (release {}, commit {}), profiles [{}], readiness {}, port {}, management port {}, upstreams {}",
                        version, tag, revision, profiles, readiness, value(port), management == null ? "same as server" : management, upstreams);
    }

    @EventListener
    public void closed(ContextClosedEvent event) {
        if (event.getApplicationContext() != context) return;  // the management child context closes too
        ReadinessState last = phase == Phase.STOPPING ? readinessBeforeStop : readiness;
        phase = Phase.STOPPING;
        long uptime = uptimeMillis.getAsLong() / 1000;
        boolean wasReady = summarized.get();
        LIFECYCLE.atInfo().addKeyValue("event.action", "shutdown.requested").addKeyValue("uptimeSeconds", uptime)
                .addKeyValue("readiness.last", last == null ? "NONE" : last.name()).addKeyValue("ready.reached", wasReady)
                .log("{}; uptime {} s, readiness until now {}", wasReady ? STOPPING : STOPPING_UNREADY, uptime, last == null ? "not reported" : last);
    }

    /** The configured upstreams as {@code name=host[:port]}; Cognito by region only. Unset ones are left out. */
    String upstreams() {
        List<String> names = new ArrayList<>();
        add(names, "domain", property("app.oauth.domain-api-upstream"));
        add(names, "web", property("app.gateway.web-upstream"));
        add(names, "identity", property("app.oauth.identity-upstream"));
        if ("true".equals(property("app.author-previews.enabled"))) add(names, "author-previews", property("app.author-previews.upstream"));
        String issuer = property("app.cognito.issuer");
        if (issuer != null && !issuer.isBlank()) {
            String host = host(issuer, false);
            String[] labels = host == null ? new String[0] : host.split("\\.");
            names.add("cognito=" + (labels.length > 1 && labels[0].equals("cognito-idp") ? labels[1] : "configured"));
        }
        return names.isEmpty() ? "none" : String.join(" ", names);
    }

    private static void add(List<String> names, String name, String origin) {
        if (origin == null || origin.isBlank()) return;
        String host = host(origin, true);
        names.add(name + "=" + (host == null ? "unparseable" : host));
    }

    /** Host and (when {@code port}) port of a URI: never its user, path or query. Null when it does not parse. */
    static String host(String origin, boolean port) {
        try {
            URI uri = URI.create(origin.strip());
            if (uri.getHost() == null) return null;
            return port && uri.getPort() >= 0 ? uri.getHost() + ":" + uri.getPort() : uri.getHost();
        } catch (IllegalArgumentException unparseable) {
            return null;
        }
    }

    /** A property, or null when it is unset or its placeholder does not resolve (the message would quote the value). */
    private String property(String name) {
        try {
            return environment.getProperty(name);
        } catch (IllegalArgumentException unresolved) {
            return null;
        }
    }

    private static String value(String value) { return value == null || value.isBlank() ? "unset" : value; }

    private static String type(Object source) { return source == null ? "unknown" : source.getClass().getSimpleName(); }
}
