package com.lookahead.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Browser token custody and fixed upstream routing. The application has no database of its own; in
 * DEV it reads one DynamoDB item, the DEV session status, through {@code db/store/DevSessionStore}.
 */
@SpringBootApplication(scanBasePackages = {"com.lookahead.gateway"})
public class GatewayBffApplication {
  public static void main(String[] args) {
    var app = new SpringApplication(GatewayBffApplication.class);
    app.setAdditionalProfiles("gateway");
    app.run(args);
  }
}
