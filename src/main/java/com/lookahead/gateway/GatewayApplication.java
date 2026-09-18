package com.lookahead.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Browser token custody and fixed upstream routing; no database access. */
@SpringBootApplication(scanBasePackages = {"com.lookahead.gateway", "com.lookahead.learning.content.gateway", "com.lookahead.learning.content.oauth"})
public class GatewayApplication {
    public static void main(String[] args) {
        var app = new SpringApplication(GatewayApplication.class);
        app.setAdditionalProfiles("gateway");
        app.run(args);
    }
}
