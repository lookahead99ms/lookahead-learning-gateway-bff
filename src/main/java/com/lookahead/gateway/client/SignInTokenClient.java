package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;

/**
 * The provider tokens of a signed-in session, renewed when they are due: one call to Spring Security's authorized-client
 * manager (bean {@code oauthAuthorizedClientManager}), which asks the provider's token endpoint only when the access
 * token has to be refreshed. The answer and every exception are the manager's own, unchanged.
 */
public final class SignInTokenClient {
    private final OAuth2AuthorizedClientManager manager;

    public SignInTokenClient(OAuth2AuthorizedClientManager manager) { this.manager = manager; }

    /** The authorized client of this sign-in with a current access token, or null when the session holds no provider tokens. */
    public OAuth2AuthorizedClient authorize(Authentication authentication,HttpServletRequest request,HttpServletResponse response) {
        return manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId(OAuthClientRegistrationFactory.REGISTRATION_ID).principal(authentication)
            .attributes(a->{a.put(HttpServletRequest.class.getName(),request);a.put(HttpServletResponse.class.getName(),response);}).build());
    }
}
