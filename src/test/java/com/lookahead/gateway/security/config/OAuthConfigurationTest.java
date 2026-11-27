package com.lookahead.gateway.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.UnsatisfiedDependencyException;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/** The {@code oauthClientDetails} bean: the factory builds it after Spring has bound and checked {@code app.oauth}. */
class OAuthConfigurationTest {
    final ApplicationContextRunner runner = new ApplicationContextRunner().withUserConfiguration(OAuthConfiguration.class)
            .withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=local",
                    "app.oauth.issuer=http://127.0.0.1:4350", "app.oauth.frontend=http://127.0.0.1:4350",
                    "app.oauth.client-id=lookahead-candidate", "app.oauth.client-secret=synthetic-gateway-secret-never-used-outside-test",
                    "app.oauth.identity-upstream=http://identity:8080", "app.oauth.domain-api-upstream=http://domain-api:8080");

    @Test void buildsTheClientDetailsFromTheEnvironment() {
        runner.run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(OAuthConfigValues.class);
            assertThat(context.getBean(OAuthClientDetails.class).domainApiUpstream()).isEqualTo("http://domain-api:8080");
        });
    }

    /**
     * The bean method takes the bound {@link OAuthConfigValues} although its body does not read them: a wrong timeout is
     * therefore refused while Spring binds {@code app.oauth} for that parameter, before the factory binds it again.
     */
    @Test void wrongTimeoutIsRefusedWhileTheValuesAreBoundBeforeTheFactoryRuns() {
        runner.withPropertyValues("app.oauth.connect-timeout=1m").run(context -> {
            Throwable refused = context.getStartupFailure();
            assertThat(refused).isInstanceOf(UnsatisfiedDependencyException.class)
                    .hasMessageContaining("Error creating bean with name 'oauthClientDetails'")
                    .hasMessageContaining("Unsatisfied dependency expressed through method 'oauthClientDetails' parameter 0")
                    .hasRootCauseInstanceOf(IllegalStateException.class).hasRootCauseMessage("Gateway HTTP timeout outside supported range");
            assertThat(refused.getCause()).isInstanceOf(ConfigurationPropertiesBindException.class);
        });
        runner.withPropertyValues("app.oauth.read-timeout=abc").run(context -> {
            Throwable refused = context.getStartupFailure();
            assertThat(refused).isInstanceOf(UnsatisfiedDependencyException.class)
                    .hasRootCauseInstanceOf(IllegalArgumentException.class).hasRootCauseMessage("'abc' is not a valid duration");
            assertThat(refused.getCause()).isInstanceOf(ConfigurationPropertiesBindException.class);
        });
    }
}
