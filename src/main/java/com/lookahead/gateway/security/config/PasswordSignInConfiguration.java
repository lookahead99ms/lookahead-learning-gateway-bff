package com.lookahead.gateway.security.config;

import com.lookahead.gateway.client.PasswordSignInCognitoClient;
import com.lookahead.gateway.security.handler.PasswordSignInHandler;
import com.lookahead.gateway.security.handler.PasswordSignInThrottle;
import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.PasswordSignInSession;
import java.time.Clock;
import java.time.Duration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import software.amazon.awssdk.auth.credentials.AnonymousCredentialsProvider;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.DefaultRetryStrategy;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;

/** What our own sign-in and sign-up pages work with: the Cognito connection and the client that calls through it, the attempt throttle, the session helper and the handler behind the routes. */
@Configuration
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
public class PasswordSignInConfiguration {
    /** Anonymous: these are Cognito's public client operations, authorised by the client id and SECRET_HASH. */
    @Bean(destroyMethod = "") public CognitoIdentityProviderClient passwordSignInCognitoIdp(OAuthClientDetails oauth) {
        String region = OAuthClientDetails.region(oauth.issuer());
        return CognitoIdentityProviderClient.builder().region(Region.of(region))
            .credentialsProvider(AnonymousCredentialsProvider.create())
            .httpClientBuilder(UrlConnectionHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(3)).socketTimeout(Duration.ofSeconds(5)))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(8)).apiCallAttemptTimeout(Duration.ofSeconds(5))
                .retryStrategy(DefaultRetryStrategy.doNotRetry()))
            .build();
    }
    @Bean public PasswordSignInCognitoClient passwordSignInCognitoClient(OAuthClientDetails oauth) {
        return new PasswordSignInCognitoClient(passwordSignInCognitoIdp(oauth), oauth);
    }
    /** In memory, one per running task, on the system clock. */
    @Bean public PasswordSignInThrottle passwordSignInThrottle() {
        return new PasswordSignInThrottle(Clock.systemUTC());
    }
    @Bean public PasswordSignInSession passwordSignInSession(ClientRegistrationRepository registrations,
            JwtDecoderFactory<ClientRegistration> idDecoders,
            OAuth2AuthorizedClientRepository clients,
            SignInCompletionHandler completion) {
        return new PasswordSignInSession(registrations, idDecoders, clients, completion, Clock.systemUTC());
    }
    /** What the seven routes of {@code PasswordSignInController} do. */
    @Bean public PasswordSignInHandler passwordSignInHandler(PasswordSignInCognitoClient cognito, PasswordSignInThrottle throttle, PasswordSignInSession sessions) {
        return new PasswordSignInHandler(cognito, throttle, sessions);
    }
}
