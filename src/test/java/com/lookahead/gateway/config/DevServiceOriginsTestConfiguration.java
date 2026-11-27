package com.lookahead.gateway.config;

import com.lookahead.gateway.util.DevServiceOrigins;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

/**
 * For tests that load the clients and forwarders over a plain connection of their own, without
 * {@code UpstreamHttpConfiguration}: the DEV origins bean exactly as that class declares it (its own bean method, lazy, the same two profiles).
 * A {@code @TestConfiguration}, so the component scan of a test that starts the whole application leaves it out.
 */
@TestConfiguration
@Profile("gateway")
public class DevServiceOriginsTestConfiguration {
    @Bean @Lazy @Profile("lower-cost-dev") DevServiceOrigins devServiceOrigins(Environment environment) {
        return new UpstreamHttpConfiguration().devServiceOrigins(environment);
    }
}
