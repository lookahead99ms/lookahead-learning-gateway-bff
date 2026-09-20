package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.client.RestClient;
import org.springframework.web.filter.OncePerRequestFilter;

/** No cached validity: Identity-backed Domain verification protects every private BFF request. */
final class LogicalSignInFilter extends OncePerRequestFilter {
    private final OAuth2AuthorizedClientManager clients;
    private final RestClient http;
    private final OAuthSettings settings;

    LogicalSignInFilter(OAuth2AuthorizedClientManager clients, RestClient http, OAuthSettings settings) {
        this.clients = clients;
        this.http = http;
        this.settings = settings;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.startsWith("/bff/api/v1/") || path.startsWith("/bff/author/previews/"))
                || path.equals("/bff/api/v1/auth/logout");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            chain.doFilter(request, response);
            return;
        }
        int status;
        try {
            var client = clients.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead")
                    .principal(authentication).attributes(attributes -> {
                        attributes.put(HttpServletRequest.class.getName(), request);
                        attributes.put(HttpServletResponse.class.getName(), response);
                    }).build());
            status = client == null ? 401 : http.get().uri(settings.domainApiUpstream() + "/api/v1/auth/me")
                    .headers(headers -> headers.setBearerAuth(client.getAccessToken().getTokenValue()))
                    .exchange((sent, received) -> received.getStatusCode().value());
        } catch (OAuth2AuthorizationException rejected) {
            status = "invalid_grant".equals(rejected.getError().getErrorCode()) ? 401 : 503;
        } catch (RuntimeException unavailable) {
            status = 503;
        }
        if (status == 200) {
            chain.doFilter(request, response);
            return;
        }
        if (status == 401) {
            var session = request.getSession(false);
            if (session != null) session.invalidate();
            SecurityContextHolder.clearContext();
        }
        response.setStatus(status == 401 ? 401 : 503);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.getWriter().write(status == 401
                ? "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in again.\"}"
                : "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Sign-in verification is temporarily unavailable.\"}");
    }
}
