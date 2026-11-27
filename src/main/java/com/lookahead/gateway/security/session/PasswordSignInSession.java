package com.lookahead.gateway.security.session;

import com.lookahead.gateway.client.PasswordSignInCognitoClient;
import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import com.lookahead.gateway.util.SignInReturnDestination;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/** The session side of our own sign-in pages: the pending sign-in step, and the signed-in session built from the tokens Cognito returned. */
public final class PasswordSignInSession {
    public static final String PENDING = "lookaheadPasswordChallenge";
    public record Pending(String username, String challenge, String session, Instant expires, String returnTo) implements Serializable {}
    /** Cognito keeps a challenge session for three minutes. */
    static final Duration CHALLENGE_WINDOW = Duration.ofMinutes(3);

    private final ClientRegistrationRepository registrations;
    private final JwtDecoderFactory<ClientRegistration> idDecoders;
    private final OAuth2AuthorizedClientRepository clients;
    private final SignInCompletionHandler completion;
    private final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();
    private final Clock clock;

    public PasswordSignInSession(ClientRegistrationRepository registrations,
            JwtDecoderFactory<ClientRegistration> idDecoders,
            OAuth2AuthorizedClientRepository clients,
            SignInCompletionHandler completion,
            Clock clock) {
        this.registrations = registrations; this.idDecoders = idDecoders; this.clients = clients; this.completion = completion; this.clock = clock;
    }

    /** Builds the OAuth-equivalent session from Cognito's tokens and runs the shared completion; returns the next path. */
    public String finish(HttpServletRequest request, HttpServletResponse response, String returnTo, PasswordSignInCognitoClient.Tokens tokens) {
        var registration = registrations.findByRegistrationId(OAuthClientRegistrationFactory.REGISTRATION_ID);
        var decoded = idDecoders.createDecoder(registration).decode(tokens.idToken());
        if (!"id".equals(decoded.getClaimAsString("token_use"))) throw new IllegalStateException("Not an ID token");
        var idToken = new OidcIdToken(decoded.getTokenValue(), decoded.getIssuedAt(), decoded.getExpiresAt(), decoded.getClaims());
        List<GrantedAuthority> authorities = List.of(new OidcUserAuthority(idToken), new SimpleGrantedAuthority("SCOPE_aws.cognito.signin.user.admin"));
        var user = new DefaultOidcUser(authorities, idToken, "sub");
        Instant now = clock.instant();
        int lifetime = tokens.expiresIn() == null || tokens.expiresIn() <= 0 ? 300 : tokens.expiresIn();
        var access = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, tokens.accessToken(), now, now.plusSeconds(lifetime), Set.of("aws.cognito.signin.user.admin"));
        var refresh = tokens.refreshToken() == null ? null : new OAuth2RefreshToken(tokens.refreshToken(), now);
        // A fresh session id for the signed-in session, as the OAuth callback does (session fixation).
        var session = request.getSession(true);
        request.changeSessionId();
        session.removeAttribute(PENDING);
        session.setAttribute(SignInReturnDestination.SESSION_ATTRIBUTE, returnTo);
        var authentication = new OAuth2AuthenticationToken(user, authorities, registration.getRegistrationId());
        var context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);
        contexts.saveContext(context, request, response);
        clients.saveAuthorizedClient(new OAuth2AuthorizedClient(registration, authentication.getName(), access, refresh), authentication, request, response);
        return completion.completeSignIn(request, response, authentication);
    }

    /** The sign-in step this browser session is waiting on; null when there is none or its window has passed (it is removed then). */
    public Pending pending(HttpSession session) {
        if (session == null || !(session.getAttribute(PENDING) instanceof Pending pending) || !pending.expires().isAfter(clock.instant())) {
            if (session != null) session.removeAttribute(PENDING);
            return null;
        }
        return pending;
    }

    /** The pending step was answered: it is removed, so it cannot be answered a second time. */
    public void answered(HttpSession session) {
        session.removeAttribute(PENDING);
    }

    /** Keeps the sign-in step Cognito asked for next, under Cognito's own name for it, until it is answered or its window passes. */
    public void keep(HttpServletRequest request, String username, String challenge, String session, String returnTo) {
        request.getSession(true).setAttribute(PENDING, new Pending(username, challenge, session, clock.instant().plus(CHALLENGE_WINDOW), returnTo));
    }
}
