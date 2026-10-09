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
    @org.springframework.boot.autoconfigure.condition.ConditionalOnExpression("'${app.deployment-environment:local}' == 'local'")
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
                                              GatewaySecurityHandlers handlers,
                                              org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager manager,
                                              org.springframework.web.client.RestClient gatewayHttp,
                                              com.lookahead.learning.content.oauth.OAuthSettings settings) throws Exception {
        http.addFilterAfter(new LogicalSignInFilter(manager, gatewayHttp, settings),
                org.springframework.security.web.context.SecurityContextHolderFilter.class);
        var resolver=new DefaultOAuth2AuthorizationRequestResolver(clients,"/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(builder->{
            OAuth2AuthorizationRequestCustomizers.withPkce().accept(builder);
            if(settings.cloud())builder.additionalParameters(p->p.put("prompt","login"));
        });
        http.headers(headers -> headers.frameOptions(frame -> frame.disable())
                .addHeaderWriter(new GatewayFrameHeaders()));
        http.csrf(csrf->csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
                .httpBasic(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable).requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session->session.sessionFixation(fixation->fixation.changeSessionId()))
                .authorizeHttpRequests(auth->auth
                        .requestMatchers("/bff/login","/bff/logout/complete","/bff/api/v1/auth/csrf","/oauth2/authorization/**","/login/oauth2/code/**","/content/**","/actuator/health","/actuator/health/**","/api/v1/auth/options","/api/v1/auth/csrf").permitAll()
                        .requestMatchers(org.springframework.http.HttpMethod.GET, "/bff/author/previews/**").authenticated()
                        .requestMatchers(org.springframework.http.HttpMethod.HEAD, "/bff/author/previews/**").authenticated()
                        .requestMatchers("/bff/api/v1/**","/api/v1/account/**","/api/v1/auth/sign-in-challenge/**").authenticated().anyRequest().denyAll())
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
            return path.equals("/") || path.equals("/account") || path.equals("/delivery-plan")
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
