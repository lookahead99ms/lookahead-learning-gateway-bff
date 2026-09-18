package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClientException;

@RestController
@Profile("gateway")
@ConditionalOnProperty(name = "app.author-previews.enabled", havingValue = "true")
class AuthorPreviewController {
    private final OAuth2AuthorizedClientManager manager;
    private final AuthorPreviewProxy previews;

    AuthorPreviewController(OAuth2AuthorizedClientManager manager, AuthorPreviewProxy previews) {
        this.manager = manager;
        this.previews = previews;
    }

    @RequestMapping(value = "/bff/author/previews/**", method = {RequestMethod.GET, RequestMethod.HEAD})
    ResponseEntity<byte[]> preview(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken) || !authentication.isAuthenticated()) {
            return AuthorPreviewProxy.empty(401);
        }
        try {
            var client = manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead")
                    .principal(authentication).attributes(attributes -> {
                        attributes.put(HttpServletRequest.class.getName(), request);
                        attributes.put(HttpServletResponse.class.getName(), response);
                    }).build());
            if (client == null) return AuthorPreviewProxy.empty(401);
            return previews.fetch(request.getMethod(), request.getRequestURI(), request.getQueryString(),
                    client.getAccessToken().getTokenValue());
        } catch (OAuth2AuthorizationException error) {
            return AuthorPreviewProxy.empty(401);
        } catch (RestClientException error) {
            return AuthorPreviewProxy.empty(503);
        }
    }
}
