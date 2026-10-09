package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.env.MockEnvironment;
import static org.assertj.core.api.Assertions.*;

/** Exercise deployed environment names through the actual application.yml placeholders. */
class GatewayEnvironmentBindingsTest {
    static MockEnvironment cloudEnvironment(String mode) throws Exception {
        var environment = yamlEnvironment(mode);
        String region = mode.equals("dev") ? "us-east-2" : "us-west-2";
        return environment
                .withProperty("LOOKAHEAD_FRONTEND_ORIGIN", "https://" + mode + "-learn.example.test")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "https://" + mode + "-domain.example.test")
                .withProperty("LOOKAHEAD_COGNITO_ISSUER", "https://cognito-idp." + region + ".amazonaws.com/" + region + "_Example")
                .withProperty("LOOKAHEAD_COGNITO_MANAGED_LOGIN", "https://" + mode + "-example.auth." + region + ".amazoncognito.com")
                .withProperty("LOOKAHEAD_COGNITO_SCOPE_PREFIX", "lookahead-" + mode)
                .withProperty("APP_OAUTH_CLIENT_ID", "synthetic" + mode + "client12345")
                .withProperty("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-" + mode + "-internal-secret-not-for-deployment")
                .withProperty("LOOKAHEAD_GATEWAY_COOKIE_NAME", "LOOKAHEAD_" + mode.toUpperCase() + "_GATEWAY");
    }

    private static MockEnvironment yamlEnvironment(String mode) throws Exception {
        var environment = new MockEnvironment()
                .withProperty("LOOKAHEAD_ENVIRONMENT", mode)
                .withProperty("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "synthetic-" + mode + "-client-secret-not-for-deployment");
        environment.setActiveProfiles("gateway", mode);
        new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"))
                .forEach(source -> environment.getPropertySources().addLast(source));
        return environment;
    }

    @Test void localYamlKeepsIdentityHttpAndNeverRequiresCognitoSettings() throws Exception {
        var environment = yamlEnvironment("local")
                .withProperty("LOOKAHEAD_FRONTEND_ORIGIN", "http://127.0.0.1:4301")
                .withProperty("LOOKAHEAD_OAUTH_ISSUER", "http://127.0.0.1:4301")
                .withProperty("LOOKAHEAD_IDENTITY_UPSTREAM", "http://identity:8080")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain-api:8080");
        var settings = OAuthSettings.from(environment);
        var registration = new GatewayClientConfiguration().gatewayClient(settings).findByRegistrationId("lookahead");
        assertThat(settings.cloud()).isFalse();
        assertThat(settings.gatewaySecret()).isNull();
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("http://127.0.0.1:4301/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo("http://identity:8080/oauth2/token");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("http://identity:8080/oauth2/jwks");
        assertThat(registration.getScopes()).containsExactlyInAnyOrder("openid", "profile", "account", "content", "support");
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void cloudYamlWiresOwnProviderScopesSecretsAndSecureCookiesWithoutIdentity(String mode) throws Exception {
        var environment = cloudEnvironment(mode);
        var settings = OAuthSettings.from(environment);
        var registration = new GatewayClientConfiguration().gatewayClient(settings).findByRegistrationId("lookahead");
        String region = mode.equals("dev") ? "us-east-2" : "us-west-2";
        assertThat(settings.cloud()).isTrue();
        assertThat(settings.identityUpstream()).isNull();
        assertThat(settings.frontend()).isEqualTo("https://" + mode + "-learn.example.test");
        assertThat(settings.domainApiUpstream()).isEqualTo("https://" + mode + "-domain.example.test");
        assertThat(settings.gatewaySecret()).isEqualTo("synthetic-" + mode + "-internal-secret-not-for-deployment");
        assertThat(registration.getClientId()).isEqualTo("synthetic" + mode + "client12345");
        assertThat(registration.getRedirectUri()).isEqualTo("https://" + mode + "-learn.example.test/login/oauth2/code/lookahead");
        assertThat(registration.getProviderDetails().getAuthorizationUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/authorize");
        assertThat(registration.getProviderDetails().getTokenUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/token");
        assertThat(registration.getProviderDetails().getUserInfoEndpoint().getUri()).isEqualTo("https://" + mode + "-example.auth." + region + ".amazoncognito.com/oauth2/userInfo");
        assertThat(registration.getProviderDetails().getJwkSetUri()).isEqualTo("https://cognito-idp." + region + ".amazonaws.com/" + region + "_Example/.well-known/jwks.json");
        assertThat(registration.getScopes()).containsExactlyInAnyOrder("openid", "profile", "email", "aws.cognito.signin.user.admin", "lookahead-" + mode + "/account", "lookahead-" + mode + "/content", "lookahead-" + mode + "/support");
        assertThat(environment.getProperty("server.servlet.session.cookie.secure", Boolean.class)).isTrue();
        assertThat(environment.getProperty("server.servlet.session.cookie.http-only", Boolean.class)).isTrue();
        assertThat(environment.getProperty("server.servlet.session.cookie.same-site")).isEqualTo("lax");
        assertThat(environment.getProperty("server.servlet.session.cookie.name")).isEqualTo("LOOKAHEAD_" + mode.toUpperCase() + "_GATEWAY");
        assertThat(settings.toString()).doesNotContain(settings.clientSecret(), settings.gatewaySecret());
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void serviceConnectAcceptsOnlyTheSelectedLocalProxyAliasAndKeepsProviderHttps(String mode) throws Exception {
        var environment = cloudEnvironment(mode)
                .withProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "service-connect-tls")
                .withProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain:8080");
        var settings = OAuthSettings.from(environment);
        assertThat(settings.domainApiUpstream()).isEqualTo("http://domain:8080");
        var provider = new GatewayClientConfiguration().gatewayClient(settings)
                .findByRegistrationId("lookahead").getProviderDetails();
        assertThat(provider.getTokenUri()).startsWith("https://");
        assertThat(provider.getJwkSetUri()).startsWith("https://cognito-idp.");
        assertThat(provider.getUserInfoEndpoint().getUri()).startsWith("https://");
        for (String endpoint : new String[]{"http://domain", "http://domain:80", "http://domain:8081",
                "http://domain-api:8080", "http://127.0.0.1:8080", "http://localhost:8080",
                "http://domain.lookahead-dev.internal:8080", "http://domain.attacker.test:8080",
                "http://domain:8080/", "http://domain:8080/api", "http://domain:8080?x=y",
                "http://domain:8080#fragment", "http://user@domain:8080", "http://domain:8080@attacker.test",
                "http://DOMAIN:8080", "http://%64omain:8080", "https://domain:8080", " http://domain:8080"}) {
            environment.setProperty("LOOKAHEAD_DOMAIN_UPSTREAM", endpoint);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(mode + " rejects " + endpoint)
                    .isInstanceOf(IllegalStateException.class);
        }
        for (String transport : new String[]{"", "http", "service-connect", "SERVICE-CONNECT-TLS", "service-connect-tls "}) {
            environment.setProperty("LOOKAHEAD_DOMAIN_TRANSPORT", transport);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(mode + " rejects mode " + transport)
                    .isInstanceOf(IllegalStateException.class);
        }
        environment.setProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "https");
        environment.setProperty("LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain:8080");
        assertThatThrownBy(() -> OAuthSettings.from(environment)).isInstanceOf(IllegalStateException.class);
    }

    @Test void localCannotAccidentallySelectCloudServiceConnectTransport() throws Exception {
        var environment = yamlEnvironment("local")
                .withProperty("LOOKAHEAD_DOMAIN_TRANSPORT", "service-connect-tls");
        assertThatThrownBy(() -> OAuthSettings.from(environment)).isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("requires DEV/PROD");
    }

    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void eachCloudEnvironmentRejectsMissingCredentialsUnsafeOriginsAndCrossRegionProvider(String mode) throws Exception {
        String[][] invalid = {
                {"LOOKAHEAD_GATEWAY_CLIENT_SECRET", ""}, {"LOOKAHEAD_DOMAIN_GATEWAY_SECRET", ""},
                {"APP_OAUTH_CLIENT_ID", "lookahead-web-gateway"}, {"LOOKAHEAD_COGNITO_SCOPE_PREFIX", "bad scope"},
                {"LOOKAHEAD_COGNITO_ISSUER", "https://identity.example.test"},
                {"LOOKAHEAD_COGNITO_ISSUER", "https://cognito-idp.us-east-2.amazonaws.com/us-west-2_Example"},
                {"LOOKAHEAD_COGNITO_MANAGED_LOGIN", "https://example.auth.eu-west-1.amazoncognito.com"},
                {"LOOKAHEAD_FRONTEND_ORIGIN", "http://127.0.0.1:4301"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "http://domain-api:8080"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://user:password@domain.example.test"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test/path"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test?redirect=elsewhere"},
                {"LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.example.test#fragment"}
        };
        for (var setting : invalid) {
            var environment = cloudEnvironment(mode).withProperty(setting[0], setting[1]);
            assertThatThrownBy(() -> OAuthSettings.from(environment)).as(mode + " rejects " + setting[0]).isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> OAuthSettings.from(cloudEnvironment(mode).withProperty("server.servlet.session.cookie.secure", "false"))).isInstanceOf(IllegalStateException.class);
        var mixed = cloudEnvironment(mode); mixed.setActiveProfiles("gateway", "local");
        assertThatThrownBy(() -> OAuthSettings.from(mixed)).isInstanceOf(IllegalStateException.class);
    }
}
