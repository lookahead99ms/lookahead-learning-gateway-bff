package com.lookahead.gateway.security.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.lookahead.gateway.controller.PasswordSignInController;
import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import java.net.URI;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;

/** DLV-969: the beans of the password pages, built by calling the bean methods directly. */
class PasswordSignInConfigurationTest {
    final OAuthClientDetails oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    final ClientRegistrationRepository registrations = new OAuthClientConfiguration().oauthClientRegistrations(oauth);
    final HttpSessionOAuth2AuthorizedClientRepository clients = new HttpSessionOAuth2AuthorizedClientRepository();
    final SignInCompletionHandler completion = mock(SignInCompletionHandler.class);
    final MutableClock clock = new MutableClock(Instant.parse("2026-11-02T20:00:00Z"));
    String tokenUse = "id";
    final JwtDecoderFactory<ClientRegistration> idDecoders = registration -> token -> Jwt.withTokenValue(token).header("alg", "RS256")
        .issuer(oauth.issuer()).subject("synthetic-subject").audience(List.of(oauth.clientId()))
        .issuedAt(clock.instant()).expiresAt(clock.instant().plusSeconds(300)).claim("auth_time", clock.instant())
        .claim("token_use", tokenUse).claim("cognito:username", "priya@example.invalid").build();
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }
    @Test void productionConstructorBuildsAnAnonymousRegionalClient() {
        var configuration = new PasswordSignInConfiguration();
        var built = configuration.passwordSignInCognitoIdp(oauth);
        assertThat(built.serviceClientConfiguration().region().id()).isEqualTo(URI.create(oauth.issuer()).getHost().split("\\.")[1]);
        built.close();
        assertThat(new PasswordSignInController(configuration.passwordSignInHandler(configuration.passwordSignInCognitoClient(oauth), configuration.passwordSignInThrottle(),
            configuration.passwordSignInSession(registrations, idDecoders, clients, completion)))).isNotNull();
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
