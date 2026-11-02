package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import java.util.EnumMap;
import java.util.Map;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Builds the Cognito authorization request. Every request uses PKCE. In cloud mode the default (no provider chosen)
 * keeps {@code prompt=login}; a chosen provider adds {@code identity_provider} and that provider's prompt (DLV-969).
 * Local mode ignores the provider: the local Identity service has its own sign-in page.
 */
final class ProviderAwareResolver implements OAuth2AuthorizationRequestResolver {
    static final String AUTHORIZATION_BASE = "/oauth2/authorization";
    private final OAuth2AuthorizationRequestResolver standard;
    private final Map<SignInProvider, OAuth2AuthorizationRequestResolver> chosen = new EnumMap<>(SignInProvider.class);
    private final boolean cloud;
    private final boolean googleEnabled;

    ProviderAwareResolver(ClientRegistrationRepository clients, boolean cloud, boolean googleEnabled) {
        this.cloud = cloud; this.googleEnabled = googleEnabled;
        this.standard = resolver(clients, cloud ? "login" : null, null);
        for (var provider : SignInProvider.values()) chosen.put(provider, resolver(clients, provider.prompt, provider.cognitoName));
    }

    private static OAuth2AuthorizationRequestResolver resolver(ClientRegistrationRepository clients, String prompt, String identityProvider) {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, AUTHORIZATION_BASE);
        resolver.setAuthorizationRequestCustomizer(builder -> {
            OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
            builder.additionalParameters(parameters -> {
                if (prompt != null) parameters.put("prompt", prompt);
                if (identityProvider != null) parameters.put("identity_provider", identityProvider);
            });
        });
        return resolver;
    }

    private OAuth2AuthorizationRequestResolver pick(HttpServletRequest request) {
        if (!cloud) return standard;
        return SignInProvider.from(request.getParameter(SignInProvider.PARAMETER), googleEnabled).map(chosen::get).orElse(standard);
    }

    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request) { return pick(request).resolve(request); }

    @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return pick(request).resolve(request, clientRegistrationId);
    }
}
