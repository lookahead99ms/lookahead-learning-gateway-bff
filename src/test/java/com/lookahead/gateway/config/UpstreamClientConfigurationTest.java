package com.lookahead.gateway.config;

import com.lookahead.gateway.client.SignInCognitoClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInIdentityClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.client.TestSessionDomainClient;
import com.lookahead.gateway.proxy.AccountCloudProxy;
import com.lookahead.gateway.proxy.AccountIdentityProxy;
import com.lookahead.gateway.proxy.AccountMergeProxy;
import com.lookahead.gateway.proxy.DevWebProxy;
import com.lookahead.gateway.proxy.DomainProxy;
import com.lookahead.gateway.proxy.IdentityProxy;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.util.DevServiceOrigins;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.client.RestClient;
import static org.assertj.core.api.Assertions.assertThat;

/** DLV-1015: each client and forwarder is a bean in exactly the modes in which the class that uses it exists. */
class UpstreamClientConfigurationTest {
    private static final OAuthClientDetails OAUTH = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-test",
            "synthetic-client-secret-only-for-testing", "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(UpstreamClientConfiguration.class, DevServiceOriginsTestConfiguration.class)
            .withBean(OAuthClientDetails.class, () -> OAUTH)
            .withBean("upstreamHttp", RestClient.class, RestClient::create)
            .withBean(OAuth2AuthorizedClientManager.class, () -> request -> null)
            .withBean(OAuth2AuthorizedClientRepository.class, HttpSessionOAuth2AuthorizedClientRepository::new);

    @Test void localModeHasTheIdentityForwarderAndNoCloudOrDevClient() {
        for (String environment : new String[]{"app.deployment-environment=local", "unset.deployment-environment=true"}) {
            runner.withPropertyValues("spring.profiles.active=gateway", environment).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(SignInDomainClient.class).hasSingleBean(DomainProxy.class)
                        .hasSingleBean(IdentityProxy.class).doesNotHaveBean(AccountMergeProxy.class)
                        .doesNotHaveBean(TestSessionDomainClient.class).doesNotHaveBean(DevWebProxy.class)
                        .doesNotHaveBean(AccountCloudProxy.class).hasSingleBean(AccountIdentityProxy.class);
                assertThat(context.getBeanNamesForType(Object.class)).contains("signInDomainClient", "domainProxy", "identityProxy", "accountIdentityProxy");
            });
        }
    }

    @Test void devModeHasTheCloudAndDevClientsAndNoIdentityForwarder() {
        runner.withPropertyValues("spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(SignInDomainClient.class).hasSingleBean(DomainProxy.class)
                            .hasSingleBean(AccountMergeProxy.class).hasSingleBean(TestSessionDomainClient.class)
                            .hasSingleBean(DevWebProxy.class).doesNotHaveBean(IdentityProxy.class)
                            .hasSingleBean(AccountCloudProxy.class).doesNotHaveBean(AccountIdentityProxy.class);
                    assertThat(context.getBeanNamesForType(Object.class))
                            .contains("signInDomainClient", "domainProxy", "accountMergeProxy", "testSessionDomainClient", "devWebProxy", "accountCloudProxy");
                });
    }

    @Test void prodModeHasTheCloudClientsOnly() {
        runner.withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=prod").run(context ->
                assertThat(context).hasNotFailed().hasSingleBean(SignInDomainClient.class).hasSingleBean(DomainProxy.class)
                        .hasSingleBean(AccountMergeProxy.class).doesNotHaveBean(TestSessionDomainClient.class)
                        .doesNotHaveBean(DevWebProxy.class).doesNotHaveBean(IdentityProxy.class)
                        .hasSingleBean(AccountCloudProxy.class).hasBean("accountCloudProxy").doesNotHaveBean(AccountIdentityProxy.class));
    }

    @Test void nothingIsCreatedOutsideTheGatewayProfile() {
        runner.withPropertyValues("spring.profiles.active=accounts,lower-cost-dev", "app.deployment-environment=dev").run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean(SignInDomainClient.class).doesNotHaveBean(DomainProxy.class)
                        .doesNotHaveBean(AccountMergeProxy.class).doesNotHaveBean(TestSessionDomainClient.class)
                        .doesNotHaveBean(DevWebProxy.class).doesNotHaveBean(IdentityProxy.class)
                        .doesNotHaveBean(AccountCloudProxy.class).doesNotHaveBean(AccountIdentityProxy.class));
    }

    @Test void theSignInControllersIdentityAndCognitoClientsExistInEveryModeAndNotOutsideTheGatewayProfile() {
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=local"},
                {"spring.profiles.active=gateway", "unset.deployment-environment=true"},
                {"spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                        DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB},
                {"spring.profiles.active=gateway", "app.deployment-environment=prod"}}) {
            runner.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(SignInIdentityClient.class).hasSingleBean(SignInCognitoClient.class);
                assertThat(context.getBeanNamesForType(Object.class)).contains("signInIdentityClient", "signInCognitoClient");
                // DLV-1015: the token client, in every mode too (the Domain relay and the sign-out use it everywhere).
                assertThat(context).hasSingleBean(SignInTokenClient.class).hasBean("signInTokenClient");
            });
        }
        runner.withPropertyValues("spring.profiles.active=accounts,lower-cost-dev", "app.deployment-environment=dev").run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean(SignInIdentityClient.class).doesNotHaveBean(SignInCognitoClient.class)
                        .doesNotHaveBean(SignInTokenClient.class));
    }

    @Test void theConfiguredIdentityCookieNamesStillStopALocalStartWhenInvalidOrSharedWithTheGateway() {
        runner.withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=local",
                "app.gateway.identity-cookie-name=bad name").run(context ->
                assertThat(context).hasFailed().getFailure().rootCause().isInstanceOf(IllegalStateException.class)
                        .hasMessage("Invalid Identity cookie name"));
        runner.withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=local",
                "server.servlet.session.cookie.name=LOOKAHEAD_SIGNIN_BINDING").run(context ->
                assertThat(context).hasFailed().getFailure().rootCause().isInstanceOf(IllegalStateException.class)
                        .hasMessage("Identity and Gateway cookies must be distinct"));
        // The same names are never read in DEV or PROD, where no Identity forwarder exists.
        runner.withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=prod",
                "app.gateway.identity-cookie-name=bad name").run(context -> assertThat(context).hasNotFailed());
    }

    @Test void aWrongWebUpstreamStillStopsADevStartAndIsNeverReadElsewhere() {
        runner.withPropertyValues("spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=https://web.attacker.test:8443")
                .run(context -> assertThat(context).hasFailed().getFailure().rootCause().isInstanceOf(IllegalStateException.class));
        runner.withPropertyValues("spring.profiles.active=gateway", "app.deployment-environment=prod",
                DevServiceOrigins.WEB_PROPERTY + "=https://web.attacker.test:8443").run(context -> assertThat(context).hasNotFailed());
    }
}
