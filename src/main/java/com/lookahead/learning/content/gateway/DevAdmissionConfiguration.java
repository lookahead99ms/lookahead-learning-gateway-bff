package com.lookahead.learning.content.gateway;

import java.time.Clock;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;

/** DLV-969: the DEV gate opens on a Look Ahead pool sign-in; no second pool, client registration or directory check. */
@Configuration @Profile("lower-cost-dev")
public class DevAdmissionConfiguration {
    @Bean org.springframework.boot.web.server.WebServerFactoryCustomizer<org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory> boundedDevSessions() {
        return factory -> factory.addContextCustomizers(context -> {
            var manager = new org.apache.catalina.session.StandardManager();
            manager.setPathname(null); manager.setMaxActiveSessions(1000); context.setManager(manager);
        });
    }
    @Bean DevGate devGate(Environment env) {
        if (!"dev".equals(env.getRequiredProperty("app.deployment-environment"))) throw new IllegalStateException("DEV profile only");
        return DevGate.freshSignIn(Clock.systemUTC());
    }
    @Bean FilterRegistrationBean<DevAdmission> admissionFilter() {
        var bean = new FilterRegistrationBean<>(new DevAdmission(Clock.systemUTC()));
        bean.setOrder(-110); return bean;
    }
    @Bean @Order(0) SecurityFilterChain admissionSecurity(HttpSecurity http) throws Exception {
        http.securityMatcher("/dev/**").securityContext(c -> c.securityContextRepository(new NullSecurityContextRepository()))
            .httpBasic(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable).requestCache(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a.anyRequest().permitAll());
        return http.build();
    }
}
