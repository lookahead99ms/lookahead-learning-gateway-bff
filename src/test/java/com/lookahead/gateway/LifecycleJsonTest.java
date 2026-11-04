package com.lookahead.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.boot.availability.AvailabilityChangeEvent;
import org.springframework.boot.availability.ReadinessState;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.info.BuildProperties;
import org.springframework.boot.logging.logback.StructuredLogEncoder;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;

/**
 * DLV-969: the DEV profile's ECS encoder renders every new lifecycle line as one JSON record. A key that collides with an
 * ECS member ({@code service.*}, {@code log.*}, {@code process.*}) makes Logback drop the whole line, so each is rendered here.
 */
class LifecycleJsonTest {
    @Test void everyLifecycleLineIsOneEcsRecord() throws Exception {
        var environment = new MockEnvironment();
        for (var source : new YamlPropertySourceLoader().load("dev", new ClassPathResource("application-lower-cost-dev.yml")))
            environment.getPropertySources().addFirst(source);
        environment.withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.lookahead-dev.internal:8443").withProperty("local.server.port", "8443");
        var context = (LoggerContext) LoggerFactory.getILoggerFactory();
        Object previous = context.getObject(Environment.class.getName());
        var out = new ByteArrayOutputStream();
        var encoder = new StructuredLogEncoder();
        var appender = new ch.qos.logback.core.OutputStreamAppender<ILoggingEvent>();
        var lifecycleLogger = (Logger) LoggerFactory.getLogger("lookahead.lifecycle");
        try {
            context.putObject(Environment.class.getName(), environment);
            encoder.setContext(context); encoder.setFormat(environment.getProperty("logging.structured.format.console")); encoder.start();
            appender.setContext(context); appender.setEncoder(encoder); appender.setOutputStream(out); appender.start();
            lifecycleLogger.addAppender(appender);
            var beans = new DefaultListableBeanFactory();
            var properties = new Properties(); properties.setProperty("version", "1.2.3");
            beans.registerSingleton("build", new BuildProperties(properties));
            var application = new GenericApplicationContext();
            var lifecycle = new LifecycleLog(application, environment, beans.getBeanProvider(BuildProperties.class), () -> 5000);
            lifecycle.availability(new AvailabilityChangeEvent<>(application, ReadinessState.ACCEPTING_TRAFFIC));
            HealthIndicator down = () -> Health.down().build();
            ((HealthIndicator) new HealthLog().postProcessAfterInitialization(down, "livenessStateHealthIndicator")).health();
            try { StartupLog.refused("app.cognito.issuer (LOOKAHEAD_COGNITO_ISSUER)", "MISSING", "fixed message"); } catch (RuntimeException ignored) { }
            lifecycle.closed(new ContextClosedEvent(application));
        } finally {
            lifecycleLogger.detachAppender(appender); appender.stop(); encoder.stop();
            if (previous != null) context.putObject(Environment.class.getName(), previous);
        }
        String[] lines = out.toString(StandardCharsets.UTF_8).strip().split("\n");
        assertThat(lines).hasSize(5);
        var mapper = new tools.jackson.databind.ObjectMapper();
        var actions = new java.util.ArrayList<String>();
        for (String line : lines) {
            var json = mapper.readTree(line);
            assertThat(json.at("/log/logger").asString()).isEqualTo("lookahead.lifecycle");
            assertThat(json.at("/service/name").asString()).isEqualTo("gateway");
            actions.add(json.at("/event/action").asString());
            assertThat(line).doesNotContain("ERROR");
        }
        assertThat(actions).containsExactly("availability.readiness", "startup.ready", "health.check", "startup.refused", "shutdown.requested");
        var summary = mapper.readTree(lines[1]);
        assertThat(summary.at("/gateway/version").asString()).isEqualTo("1.2.3");
        assertThat(summary.get("upstreams").asString()).isEqualTo("domain=domain.lookahead-dev.internal:8443");
        assertThat(mapper.readTree(lines[4]).get("uptimeSeconds").asInt()).isEqualTo(5);
    }
}
