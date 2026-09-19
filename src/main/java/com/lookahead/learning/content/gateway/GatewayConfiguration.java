package com.lookahead.learning.content.gateway;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@Profile("gateway")
@Import(GatewaySecurityHandlers.class)
public class GatewayConfiguration {
    /** Identity validates its own session and CSRF; OAuth client filters must not consume its form bodies. */
    @Bean @Order(1)
    SecurityFilterChain identityProxySecurity(HttpSecurity http) throws Exception {
        http.securityMatcher(IdentityProxyController.PATHS)
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        http.headers(headers -> headers.frameOptions(frame -> frame.disable())
                .addHeaderWriter(new GatewayFrameHeaders()));
        return http.build();
    }

    @Bean @Order(2)
    SecurityFilterChain gatewaySecurity(HttpSecurity http, ClientRegistrationRepository clients,
                                              OAuth2AuthorizedClientRepository authorized,
                                              RestClientAuthorizationCodeTokenResponseClient exchange, OidcUserService oidcUsers,
                                              GatewaySecurityHandlers handlers) throws Exception {
        var resolver=new DefaultOAuth2AuthorizationRequestResolver(clients,"/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        http.headers(headers -> headers.frameOptions(frame -> frame.disable())
                .addHeaderWriter(new GatewayFrameHeaders()));
        http.csrf(csrf->csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
                .httpBasic(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable).requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session->session.sessionFixation(fixation->fixation.changeSessionId()))
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/bff/login","/bff/api/v1/auth/csrf","/oauth2/authorization/**","/login/oauth2/code/**","/content/**","/actuator/health","/actuator/health/**").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/bff/author/previews/**").authenticated()
                        .requestMatchers(org.springframework.http.HttpMethod.HEAD, "/bff/author/previews/**").authenticated()
                        .requestMatchers("/bff/api/v1/**").authenticated().anyRequest().denyAll())
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint(handlers::authenticationRequired)
                        .accessDeniedHandler(handlers::accessDenied))
                .oauth2Login(login->login.authorizationEndpoint(endpoint->endpoint.authorizationRequestResolver(resolver))
                        .tokenEndpoint(endpoint->endpoint.accessTokenResponseClient(exchange))
                        .userInfoEndpoint(endpoint->endpoint.oidcUserService(oidcUsers))
                        .authorizedClientRepository(authorized)
                        .successHandler(handlers::loginSucceeded)
                        .failureHandler(handlers::loginFailed))
                .oauth2Client(client->client.authorizedClientRepository(authorized));
        return http.build();
    }
    public static String safeReturn(String value) {
        if (value == null || !value.startsWith("/") || unsafeRedirectCharacters(value)) return "/";
        try {
            var destination = new java.net.URI(value);
            String path = destination.getPath();
            if (destination.isAbsolute() || destination.getRawAuthority() != null || path == null
                    || path.matches(".*(?:^|/)\\.{1,2}(?:/.*|$)")
                    || unsafeRedirectCharacters(path) || unsafeRedirectCharacters(destination.getQuery())
                    || unsafeRedirectCharacters(destination.getFragment())) return "/";
            return path.equals("/") || path.equals("/account")
                    || path.matches("^/(?:study-plan|learn|grow|look-ahead|search|support|author)(?:/.*)?$")
                    ? value : "/";
        } catch (java.net.URISyntaxException invalidDestination) {
            return "/";
        }
    }

    private static boolean unsafeRedirectCharacters(String value) {
        return value != null && (value.indexOf('\\') >= 0
                || value.codePoints().anyMatch(Character::isISOControl));
    }
}
