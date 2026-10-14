package com.lookahead.learning.content.gateway;

import java.time.*;
import java.util.*;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.registration.*;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.context.NullSecurityContextRepository;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.regions.Region;

@Configuration @Profile("lower-cost-dev")
public class DevAdmissionConfiguration {
    @Bean org.springframework.boot.web.server.WebServerFactoryCustomizer<org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory> boundedDevSessions() {
        return factory -> factory.addContextCustomizers(context -> {
            var manager = new org.apache.catalina.session.StandardManager();
            manager.setPathname(null); manager.setMaxActiveSessions(1000); context.setManager(manager);
        });
    }
    @Bean CognitoIdentityProviderClient admissionDirectoryClient(Environment env) {
        if (!"dev".equals(env.getRequiredProperty("app.deployment-environment"))) throw new IllegalStateException("DEV profile only");
        return CognitoIdentityProviderClient.builder().region(Region.of(env.getRequiredProperty("app.admission.region")))
            .credentialsProvider(ContainerCredentialsProvider.builder().build())
            .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(2)).socketTimeout(Duration.ofSeconds(3)))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(5)).apiCallAttemptTimeout(Duration.ofSeconds(3))
                .retryPolicy(software.amazon.awssdk.core.retry.RetryPolicy.none())).build();
    }
    @Bean DevAdmission.Directory admissionDirectory(CognitoIdentityProviderClient client, Environment env) {
        String pool = env.getRequiredProperty("app.admission.pool-id");
        return (username, subject) -> {
            try {
                var user = client.adminGetUser(r -> r.userPoolId(pool).username(username));
                return Boolean.TRUE.equals(user.enabled()) && user.userAttributes().stream()
                    .anyMatch(a -> "sub".equals(a.name()) && subject.equals(a.value()));
            } catch (software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException missing) { return false; }
        };
    }
    @Bean FilterRegistrationBean<DevAdmission> admissionFilter(DevAdmission.Directory directory) {
        var bean = new FilterRegistrationBean<>(new DevAdmission(directory, Clock.systemUTC()));
        bean.setOrder(-110); return bean;
    }
    @Bean @Order(0) SecurityFilterChain admissionSecurity(HttpSecurity http, Environment env, DevAdmission.Directory directory,
            org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient gatewayTokenExchange,
            org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService gatewayOidcUsers) throws Exception {
        String region = env.getRequiredProperty("app.admission.region"), pool = env.getRequiredProperty("app.admission.pool-id");
        if (!region.matches("[a-z]{2}-[a-z]+-[0-9]") || !pool.matches(java.util.regex.Pattern.quote(region) + "_[A-Za-z0-9]+")) throw new IllegalArgumentException("Invalid admission pool");
        String origin = env.getRequiredProperty("app.oauth.frontend");
        String login = env.getRequiredProperty("app.admission.managed-login");
        if (!login.matches("https://[a-z0-9-]+\\.auth\\." + java.util.regex.Pattern.quote(region) + "\\.amazoncognito\\.com")) throw new IllegalArgumentException("Invalid admission origin");
        String issuer = "https://cognito-idp." + region + ".amazonaws.com/" + pool;
        if (issuer.equals(env.getRequiredProperty("app.cognito.issuer"))
                || env.getRequiredProperty("app.admission.client-id").equals(env.getRequiredProperty("app.oauth.client-id")))
            throw new IllegalArgumentException("Admission must use a separate pool and client");
        var client = ClientRegistration.withRegistrationId("admission")
            .clientId(env.getRequiredProperty("app.admission.client-id")).clientSecret(env.getRequiredProperty("app.admission.client-secret"))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(origin + "/dev/login/oauth2/code/admission").scope("openid")
            .authorizationUri(login + "/oauth2/authorize").tokenUri(login + "/oauth2/token")
            .jwkSetUri(issuer + "/.well-known/jwks.json").issuerUri(issuer).userNameAttributeName("sub").build();
        var registrations = new InMemoryClientRegistrationRepository(client);
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(registrations, "/dev/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(b -> { OAuth2AuthorizationRequestCustomizers.withPkce().accept(b); b.additionalParameters(p -> {p.put("prompt", "login"); p.put("max_age", "0");}); });
        var authorized = new HttpSessionOAuth2AuthorizedClientRepository();
        http.securityMatcher("/dev/**").securityContext(c -> c.securityContextRepository(new NullSecurityContextRepository()))
            .httpBasic(AbstractHttpConfigurer::disable).formLogin(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable).requestCache(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(a -> a.anyRequest().permitAll())
            .oauth2Login(o -> o.clientRegistrationRepository(registrations).authorizedClientRepository(authorized)
                .authorizationEndpoint(a -> a.authorizationRequestResolver(resolver))
                .redirectionEndpoint(r -> r.baseUri("/dev/login/oauth2/code/*"))
                .tokenEndpoint(t -> t.accessTokenResponseClient(gatewayTokenExchange))
                .userInfoEndpoint(u -> u.oidcUserService(gatewayOidcUsers))
                .successHandler((request, response, auth) -> {
                    var user = (OidcUser) auth.getPrincipal();
                    String username = user.getClaimAsString("cognito:username");
                    authorized.removeAuthorizedClient("admission", auth, request, response);
                    boolean enabled;
                    try { enabled = username != null && directory.enabled(username, user.getSubject()); }
                    catch (RuntimeException unavailable) { SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_UNAVAILABLE); request.getSession().invalidate(); response.setStatus(503); return; }
                    if (!enabled) { SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_DENIED); request.getSession().invalidate(); response.setStatus(403); return; }
                    var authTime = user.getIdToken().getAuthenticatedAt();
                    if (authTime == null || authTime.isBefore(Instant.now().minusSeconds(120)) || authTime.isAfter(Instant.now().plusSeconds(30))) {
                        request.getSession().invalidate(); response.setStatus(403); return;
                    }
                    request.getSession().invalidate();
                    var session = request.getSession(true); session.setMaxInactiveInterval(8 * 3600);
                    Instant now = Instant.now(); session.setAttribute(DevAdmission.ATTRIBUTE, new DevAdmission.State(username, user.getSubject(), now, now));
                    SecurityAuditFilter.record(SecurityAuditFilter.Event.ADMISSION_GRANTED);
                    response.setHeader("Cache-Control", "no-store"); response.sendRedirect(origin + "/");
                }).failureHandler((request, response, failure) -> { response.setHeader("Cache-Control", "no-store"); response.sendRedirect("/dev/access?error=authentication"); }));
        return http.build();
    }
}
