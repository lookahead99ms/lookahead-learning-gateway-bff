package com.lookahead.gateway.security.config;

import com.lookahead.gateway.client.SignInCognitoClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInIdentityClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.client.TestSessionDomainClient;
import com.lookahead.gateway.security.handler.DevAccessHandler;
import com.lookahead.gateway.security.handler.DevWebAuthorizationManager;
import com.lookahead.gateway.security.handler.FramePolicyHeaderWriter;
import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import com.lookahead.gateway.security.handler.SignInFailureHandler;
import com.lookahead.gateway.security.handler.SignInSuccessHandler;
import com.lookahead.gateway.security.handler.SignOutHandler;
import com.lookahead.gateway.security.handler.TestSessionHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.SignInProvider;
import com.lookahead.gateway.security.session.DevAccessGate;
import java.util.Optional;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/**
 * The handlers of the sign-in flow. In every mode of the {@code gateway} profile: the sign-out handler behind
 * the sign-out routes (as {@code SignInController}; {@code DevAccessHandler} uses the same one in DEV), and what the
 * sign-in security chain of {@code SecurityFilterChainConfiguration} receives: the success and failure handlers, the
 * frame policy header writer and the last authorization rule. Two more exist only where their routes do: the
 * test-session handler in DEV, and the handler of the DEV gate's own routes under the {@code lower-cost-dev} profile.
 */
@Configuration
@Profile("gateway")
public class SignInHandlerConfiguration {
    @Bean SignOutHandler signOutHandler(OAuthClientDetails oauth, SignInTokenClient tokens, OAuth2AuthorizedClientRepository clients,
            SignInDomainClient signInDomainClient, SignInIdentityClient signInIdentityClient, SignInCognitoClient signInCognitoClient,
            Environment environment) {
        return new SignOutHandler(oauth, tokens, clients, signInDomainClient, signInIdentityClient, signInCognitoClient, environment);
    }

    /** The one completion of an accepted sign-in, for the OAuth callback and our own password page; the DEV gate exists only in DEV. */
    @Bean SignInCompletionHandler signInCompletionHandler(OAuthClientDetails oauth, OAuth2AuthorizedClientRepository clients,
            SignInDomainClient signInDomainClient, Optional<DevAccessGate> gate) {
        return new SignInCompletionHandler(oauth, clients, signInDomainClient, gate);
    }

    @Bean SignInSuccessHandler signInSuccessHandler(OAuthClientDetails oauth, SignInCompletionHandler completion) {
        return new SignInSuccessHandler(oauth, completion);
    }

    @Bean SignInFailureHandler signInFailureHandler(OAuthClientDetails oauth, Optional<DevAccessGate> gate) {
        return new SignInFailureHandler(oauth, gate);
    }

    /** One instance for both security chains; it keeps no state. */
    @Bean FramePolicyHeaderWriter framePolicyHeaderWriter() {
        return new FramePolicyHeaderWriter();
    }

    /** DEV only, as {@code TestSessionController}, whose four routes it answers. */
    @Bean
    @ConditionalOnExpression("'${app.deployment-environment:}' == 'dev'")
    TestSessionHandler testSessionHandler(TestSessionDomainClient domainClient) {
        return new TestSessionHandler(domainClient);
    }

    /**
     * The {@code lower-cost-dev} profile only, as {@code DevAccessController}. Whether the gate page shows the Google button
     * ({@code app.cognito.google-sign-in}) is read here, once: the setting is fixed for the life of the application.
     */
    @Bean
    @Profile("lower-cost-dev")
    DevAccessHandler devAccessHandler(Environment environment, SignOutHandler signOut) {
        return new DevAccessHandler(SignInProvider.googleEnabled(environment), signOut);
    }

    /** Every mode; the profile is tested inside the rule, at each request, as before. */
    @Bean DevWebAuthorizationManager devWebAuthorizationManager(Environment environment) {
        return new DevWebAuthorizationManager(environment);
    }
}
