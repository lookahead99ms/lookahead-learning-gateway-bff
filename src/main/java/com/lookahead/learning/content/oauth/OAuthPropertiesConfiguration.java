package com.lookahead.learning.content.oauth;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;

@Configuration
@Profile("oauth-server | gateway")
@EnableConfigurationProperties(OAuthProperties.class)
public class OAuthPropertiesConfiguration {
    @Bean OAuthSettings oauthSettings(OAuthProperties properties, Environment environment) {
        return OAuthSettings.from(environment);
    }
}
