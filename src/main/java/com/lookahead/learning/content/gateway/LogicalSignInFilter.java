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

/**
 * Domain verification protects every private BFF request. DLV-969 S37 (user, 2026-11-03): reads of {@code /bff/api/v1/**}
 * (GET or HEAD), which the Domain verifies again on the real call, reuse a passed check for {@link #REUSE} within this
 * session and for the same person. Writes, the CSRF token and staff previews ({@code /bff/author/previews/**}) are
 * still checked on every request, so a revoked sign-in can neither write nor fetch a CSRF token.
 */
final class LogicalSignInFilter extends OncePerRequestFilter {
    static final String CHECKED = "lookaheadSignInChecked";
    static final java.time.Duration REUSE = java.time.Duration.ofSeconds(60);
    record Checked(String person, java.time.Instant at) implements java.io.Serializable {}
    private final OAuth2AuthorizedClientManager clients;
    private final RestClient http;
    private final OAuthSettings settings;
    private final java.time.Clock clock;

    LogicalSignInFilter(OAuth2AuthorizedClientManager clients, RestClient http, OAuthSettings settings) {
        this(clients, http, settings, java.time.Clock.systemUTC());
    }
    LogicalSignInFilter(OAuth2AuthorizedClientManager clients, RestClient http, OAuthSettings settings, java.time.Clock clock) {
        this.clients = clients;
        this.http = http;
        this.settings = settings;
        this.clock = clock;
    }

    @Override protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.startsWith("/bff/api/v1/") || path.startsWith("/bff/author/previews/")
                || settings.cloud() && CloudGatewaySessions.restricted(request) && path.startsWith("/content/"))
                || path.equals("/bff/api/v1/auth/logout")
                // DLV-969: our password page starts a new sign-in; like /bff/login it must work from any prior state.
                || path.startsWith("/bff/api/v1/auth/password/");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (settings.cloud() && CloudGatewaySessions.restricted(request)) {
            if (request.getRequestURI().equals("/bff/api/v1/auth/csrf")) {
                chain.doFilter(request, response);
                return;
            }
            response.setStatus(401);
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("application/json");
            response.getWriter().write("{\"code\":\"SIGN_IN_CHALLENGE_REQUIRED\",\"message\":\"Choose an active sign-in to continue.\"}");
            return;
        }
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            chain.doFilter(request, response);
            return;
        }
        var session = request.getSession(false);
        boolean api = session != null && request.getRequestURI().startsWith("/bff/api/v1/");
        boolean read = "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
        boolean reusable = api && read && !request.getRequestURI().equals("/bff/api/v1/auth/csrf");
        if (reusable && session.getAttribute(CHECKED) instanceof Checked checked && checked.person().equals(authentication.getName())
                && clock.instant().isBefore(checked.at().plus(REUSE))) {
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
                    .headers(headers -> {headers.setBearerAuth(client.getAccessToken().getTokenValue());CloudGatewaySessions.apply(settings,request,headers);})
                    .exchange((sent, received) -> received.getStatusCode().value());
        } catch (OAuth2AuthorizationException rejected) {
            status = "invalid_grant".equals(rejected.getError().getErrorCode()) ? 401 : 503;
        } catch (RuntimeException unavailable) {
            status = 503;
        }
        if (status == 200) {
            if (api) session.setAttribute(CHECKED, new Checked(authentication.getName(), clock.instant()));
            chain.doFilter(request, response);
            return;
        }
        if (status == 401) {
            DevAdmission.clearLearner(request);
        }
        response.setStatus(status == 401 ? 401 : 503);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.getWriter().write(status == 401
                ? "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in again.\"}"
                : "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Sign-in verification is temporarily unavailable.\"}");
    }
}
