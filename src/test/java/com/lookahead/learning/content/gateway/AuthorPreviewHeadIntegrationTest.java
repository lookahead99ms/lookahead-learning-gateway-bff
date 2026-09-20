package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.MapPropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oauth2Login;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.request;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Frame policy must survive the actual MVC response lifecycle, including an empty HEAD body. */
class AuthorPreviewHeadIntegrationTest {
    private AnnotationConfigWebApplicationContext context;
    private MockRestServiceServer upstream;
    private MockMvc http;

    @BeforeEach void configure() {
        context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.getEnvironment().setActiveProfiles("gateway");
        context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("author-preview-head-test",
                Map.of("app.deployment-environment", "local", "app.author-previews.enabled", "true")));
        context.register(TestApplication.class);
        context.refresh();
        upstream = context.getBean(MockRestServiceServer.class);
        http = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @AfterEach void close() {
        if (context != null) context.close();
    }

    @Test void htmlGetAndHeadShareSameOriginFramePolicy() throws Exception {
        verifyGetAndHead("focus-studio/index.html", MediaType.TEXT_HTML, "<html>synthetic preview</html>",
                "SAMEORIGIN", "frame-ancestors 'self'");
    }

    @Test void directoryIndexGetAndHeadUseTheActualHtmlContentType() throws Exception {
        verifyGetAndHead("focus-studio/", MediaType.TEXT_HTML, "<html>synthetic index</html>",
                "SAMEORIGIN", "frame-ancestors 'self'");
    }

    @Test void jsonGetAndHeadRemainUnframeable() throws Exception {
        verifyGetAndHead("preview-directory/manifest.json", MediaType.APPLICATION_JSON, "{\"entries\":[]}",
                "DENY", "frame-ancestors 'none'");
    }

    @Test void realTomcatPreservesHtmlAndJsonHeadHeadersBeforeCommittingTheEmptyBody() throws Exception {
        try (var application = new SpringApplicationBuilder(TransportApplication.class).profiles("gateway")
                .properties(Map.of("spring.config.name", "security-test", "server.port", "0",
                        "server.address", "127.0.0.1", "app.deployment-environment", "local",
                        "app.author-previews.enabled", "true", "spring.main.banner-mode", "off"))
                .run()) {
            int port = ((WebServerApplicationContext) application).getWebServer().getPort();
            var server = application.getBean(MockRestServiceServer.class);
            var assertions = new ArrayList<Executable>();
            for (var artifact : List.of(
                    new Artifact("focus-studio/index.html", MediaType.TEXT_HTML, "<html>synthetic preview</html>", "SAMEORIGIN", "'self'"),
                    new Artifact("focus-studio/", MediaType.TEXT_HTML, "<html>synthetic index</html>", "SAMEORIGIN", "'self'"),
                    new Artifact("preview-directory/manifest.json", MediaType.APPLICATION_JSON, "{\"entries\":[]}", "DENY", "'none'"))) {
                for (HttpMethod method : new HttpMethod[]{HttpMethod.GET, HttpMethod.HEAD}) {
                    server.reset();
                    server.expect(requestTo("http://domain-api:8080/api/v1/author/previews/access"))
                            .andExpect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NO_CONTENT));
                    server.expect(requestTo("http://127.0.0.1:4315/" + artifact.path())).andExpect(method(method))
                            .andRespond(withSuccess(artifact.body(), artifact.type()));
                    var response = HttpClient.newHttpClient().send(HttpRequest.newBuilder(
                                    URI.create("http://127.0.0.1:" + port + AuthorPreviewPath.PREFIX + artifact.path()))
                            .header("X-Synthetic-Preview-Identity", "author")
                            .method(method.name(), HttpRequest.BodyPublishers.noBody()).build(),
                            HttpResponse.BodyHandlers.ofString());
                    server.verify();
                    String description = method.name() + " " + artifact.path();
                    assertions.add(() -> assertThat(response.statusCode()).as(description).isEqualTo(200));
                    assertions.add(() -> assertThat(response.body()).as(description + " body")
                            .isEqualTo(method == HttpMethod.HEAD ? "" : artifact.body()));
                    assertions.add(() -> assertThat(response.headers().firstValue("Content-Type"))
                            .as(description + " content type").contains(artifact.type().toString()));
                    assertions.add(() -> assertThat(response.headers().firstValue("Cache-Control"))
                            .as(description + " cache policy").contains("private, no-store"));
                    assertions.add(() -> assertThat(response.headers().firstValue("X-Frame-Options"))
                            .as(description + " frame policy").contains(artifact.frame()));
                    assertions.add(() -> assertThat(response.headers().firstValue("Content-Security-Policy"))
                            .as(description + " CSP").contains("frame-ancestors " + artifact.ancestors()));
                }
            }
            assertAll(assertions);
        }
    }

    private record Artifact(String path, MediaType type, String body, String frame, String ancestors) { }

    private void verifyGetAndHead(String path, MediaType type, String body, String frame, String policy) throws Exception {
        var client = context.getBean(ClientRegistrationRepository.class).findByRegistrationId("lookahead");
        for (HttpMethod method : new HttpMethod[]{HttpMethod.GET, HttpMethod.HEAD}) {
            upstream.reset();
            upstream.expect(requestTo("http://domain-api:8080/api/v1/author/previews/access"))
                    .andExpect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NO_CONTENT));
            upstream.expect(requestTo("http://127.0.0.1:4315/" + path)).andExpect(method(method))
                    .andRespond(withSuccess(body, type));
            http.perform(request(method, AuthorPreviewPath.PREFIX + path)
                            .with(oauth2Login().clientRegistration(client)))
                    .andExpect(status().isOk())
                    .andExpect(content().contentType(type))
                    .andExpect(content().string(method == HttpMethod.HEAD ? "" : body))
                    .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "private, no-store"))
                    .andExpect(header().string("X-Frame-Options", frame))
                    .andExpect(header().string("Content-Security-Policy", policy));
            upstream.verify();
        }
    }

    @Configuration
    @EnableWebMvc
    @EnableWebSecurity
    @Import({ActiveSignInTestConfiguration.class, GatewayConfiguration.class, GatewayClientConfiguration.class, AuthorPreviewController.class})
    static class TestApplication {
        @Bean OAuthSettings settings() { return AuthorPreviewSettingsTest.OAUTH; }

        @Bean OAuthProperties properties() {
            var settings = AuthorPreviewSettingsTest.OAUTH;
            return new OAuthProperties(settings.issuer(), settings.frontend(), settings.clientSecret(), settings.clientId(),
                    settings.identityUpstream(), settings.domainApiUpstream(), Duration.ofSeconds(3), Duration.ofSeconds(7));
        }

        @Bean RestClient.Builder previewHttpBuilder() { return RestClient.builder(); }

        @Bean MockRestServiceServer source(RestClient.Builder previewHttpBuilder) {
            return MockRestServiceServer.bindTo(previewHttpBuilder).build();
        }

        @Bean AuthorPreviewProxy previews(RestClient.Builder previewHttpBuilder, MockRestServiceServer source,
                                          OAuthSettings settings) {
            return new AuthorPreviewProxy(new AuthorPreviewSettings(URI.create("http://127.0.0.1:4315"),
                    AuthorPreviewSettingsTest.SOURCE_SECRET), settings, previewHttpBuilder.build());
        }
    }

    @Configuration
    @EnableAutoConfiguration(excludeName = {
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
            "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration"})
    @Import(TestApplication.class)
    static class TransportApplication {
        /** Test-only identity fixture; all real gateway security filters and response writers still run. */
        @Bean static BeanPostProcessor syntheticPreviewAuthentication(
                ObjectProvider<ClientRegistrationRepository> clients,
                ObjectProvider<OAuth2AuthorizedClientRepository> authorized) {
            return new BeanPostProcessor() {
                @Override public Object postProcessAfterInitialization(Object bean, String name) {
                    if (!(bean instanceof DefaultSecurityFilterChain security)) return bean;
                    var filters = new ArrayList<Filter>(security.getFilters());
                    int authorizationIndex = -1;
                    for (int index = 0; index < filters.size(); index++) {
                        if (filters.get(index) instanceof AuthorizationFilter) authorizationIndex = index;
                    }
                    if (authorizationIndex < 0) throw new IllegalStateException("Expected the actual gateway authorization filter");
                    filters.add(authorizationIndex, new OncePerRequestFilter() {
                        @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                                                  FilterChain chain) throws ServletException, IOException {
                            if ("author".equals(request.getHeader("X-Synthetic-Preview-Identity"))) {
                                var registration = clients.getObject().findByRegistrationId("lookahead");
                                var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                                var principal = new DefaultOAuth2User(authorities, Map.of("sub", "synthetic-author"), "sub");
                                var authentication = new OAuth2AuthenticationToken(principal, authorities, "lookahead");
                                SecurityContextHolder.getContext().setAuthentication(authentication);
                                var now = Instant.now();
                                var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                                        "synthetic-server-token", now, now.plusSeconds(300));
                                authorized.getObject().saveAuthorizedClient(new OAuth2AuthorizedClient(registration,
                                        authentication.getName(), token), authentication, request, response);
                            }
                            chain.doFilter(request, response);
                        }
                    });
                    return new DefaultSecurityFilterChain(security.getRequestMatcher(), filters);
                }
            };
        }
    }
}
