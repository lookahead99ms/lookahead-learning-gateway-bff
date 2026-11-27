package com.lookahead.gateway.security.config;

import static org.assertj.core.api.Assertions.assertThat;

import com.lookahead.gateway.config.DevServiceOriginsTestConfiguration;
import com.lookahead.gateway.config.UpstreamClientConfiguration;
import com.lookahead.gateway.controller.DevAccessController;
import com.lookahead.gateway.controller.SignInController;
import com.lookahead.gateway.controller.TestSessionController;
import com.lookahead.gateway.security.handler.DevAccessHandler;
import com.lookahead.gateway.security.handler.DevWebAuthorizationManager;
import com.lookahead.gateway.security.handler.FramePolicyHeaderWriter;
import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import com.lookahead.gateway.security.handler.SignInFailureHandler;
import com.lookahead.gateway.security.handler.SignInSuccessHandler;
import com.lookahead.gateway.security.handler.SignOutHandler;
import com.lookahead.gateway.security.handler.TestSessionHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.DevAccessGate;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;

/**
 * DLV-1015: the one sign-out handler is a bean wherever SignInController exists, and both controllers receive that one;
 * and what the sign-in security chain receives (the success and failure handlers, the one completion behind the success
 * handler, the frame policy header writer and the last authorization rule) is a bean in every mode.
 */
class SignInHandlerConfigurationTest {
    private static final OAuthClientDetails OAUTH = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-test",
            "synthetic-client-secret-only-for-testing", "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(SignInHandlerConfiguration.class, UpstreamClientConfiguration.class, DevServiceOriginsTestConfiguration.class, SignInController.class, DevAccessController.class)
            .withBean(OAuthClientDetails.class, () -> OAUTH)
            .withBean("upstreamHttp", RestClient.class, RestClient::create)
            .withBean(OAuth2AuthorizedClientManager.class, () -> request -> null)
            .withBean(OAuth2AuthorizedClientRepository.class, HttpSessionOAuth2AuthorizedClientRepository::new);

    @Test void theHandlerExistsInEveryModeOfTheGatewayProfileAndTheSignInControllerReceivesIt() {
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=local"},
                {"spring.profiles.active=gateway", "unset.deployment-environment=true"},
                {"spring.profiles.active=gateway", "app.deployment-environment=prod"}}) {
            runner.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(SignOutHandler.class).hasBean("signOutHandler")
                        .hasSingleBean(SignInController.class).doesNotHaveBean(DevAccessController.class);
                assertThat(ReflectionTestUtils.getField(context.getBean(SignInController.class), "signOut")).isSameAs(context.getBean(SignOutHandler.class));
            });
        }
    }

    @Test void inDevTheLeaveRouteAndTheSignOutRouteShareTheOneHandler() {
        runner.withPropertyValues("spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(SignOutHandler.class).hasSingleBean(DevAccessController.class);
                    var handler = context.getBean(SignOutHandler.class);
                    assertThat(ReflectionTestUtils.getField(context.getBean(SignInController.class), "signOut")).isSameAs(handler);
                    // DLV-1015: the leave route asks the gate's handler, and that handler holds the one sign-out handler.
                    var gate = context.getBean(DevAccessHandler.class);
                    assertThat(ReflectionTestUtils.getField(context.getBean(DevAccessController.class), "handler")).isSameAs(gate);
                    assertThat(ReflectionTestUtils.getField(gate, "signOut")).isSameAs(handler);
                });
    }

    /** DLV-1015: the handler behind the four test-session routes exists exactly where TestSessionController does (DEV), and that controller receives it. */
    @Test void theTestSessionHandlerExistsInDevOnlyAndItsControllerReceivesIt() {
        var withController = runner.withUserConfiguration(TestSessionController.class);
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=dev"},
                {"spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                        DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB}}) {
            withController.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(TestSessionHandler.class).hasBean("testSessionHandler").hasSingleBean(TestSessionController.class);
                var handler = context.getBean(TestSessionHandler.class);
                assertThat(ReflectionTestUtils.getField(context.getBean(TestSessionController.class), "handler")).isSameAs(handler);
                assertThat(ReflectionTestUtils.getField(handler, "domainClient")).isSameAs(context.getBean("testSessionDomainClient"));
            });
        }
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=local"},
                {"spring.profiles.active=gateway", "unset.deployment-environment=true"},
                {"spring.profiles.active=gateway", "app.deployment-environment=prod"},
                {"spring.profiles.active=accounts", "app.deployment-environment=dev"}}) {
            withController.withPropertyValues(mode).run(context ->
                    assertThat(context).hasNotFailed().doesNotHaveBean(TestSessionHandler.class).doesNotHaveBean(TestSessionController.class));
        }
    }

    /** DLV-1015: the handler of the DEV gate's own routes exists under the lower-cost-dev profile only; the Google switch is read once, when it is built. */
    @Test void theDevGateHandlerExistsUnderTheLowerCostDevProfileOnlyAndKnowsTheGoogleSwitchFromTheStart() {
        for (String google : new String[]{"true", "false", null}) {
            var dev = runner.withPropertyValues("spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                    DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB);
            (google == null ? dev : dev.withPropertyValues("app.cognito.google-sign-in=" + google)).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(DevAccessHandler.class).hasBean("devAccessHandler").hasSingleBean(DevAccessController.class);
                assertThat(ReflectionTestUtils.getField(context.getBean(DevAccessHandler.class), "google")).isEqualTo("true".equals(google));
            });
        }
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=local"},
                {"spring.profiles.active=gateway", "app.deployment-environment=dev"},
                {"spring.profiles.active=gateway", "app.deployment-environment=prod"}}) {
            runner.withPropertyValues(mode).run(context ->
                    assertThat(context).hasNotFailed().doesNotHaveBean(DevAccessHandler.class).doesNotHaveBean(DevAccessController.class));
        }
    }

    @Test void outsideTheGatewayProfileThereIsNoHandler() {
        runner.withPropertyValues("spring.profiles.active=accounts", "app.deployment-environment=local").run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean(SignOutHandler.class).doesNotHaveBean(SignInController.class));
    }

    @Test void whatTheSignInChainReceivesExistsInEveryModeAndWithoutTheDevGateNoHandlerHoldsOne() {
        for (String[] mode : new String[][]{{"spring.profiles.active=gateway", "app.deployment-environment=local"},
                {"spring.profiles.active=gateway", "unset.deployment-environment=true"},
                {"spring.profiles.active=gateway", "app.deployment-environment=dev"},
                {"spring.profiles.active=gateway", "app.deployment-environment=prod"}}) {
            runner.withPropertyValues(mode).run(context -> {
                assertThat(context).hasNotFailed().hasSingleBean(SignInCompletionHandler.class).hasBean("signInCompletionHandler")
                        .hasSingleBean(SignInSuccessHandler.class).hasBean("signInSuccessHandler")
                        .hasSingleBean(SignInFailureHandler.class).hasBean("signInFailureHandler")
                        .hasSingleBean(FramePolicyHeaderWriter.class).hasBean("framePolicyHeaderWriter")
                        .hasSingleBean(DevWebAuthorizationManager.class).hasBean("devWebAuthorizationManager");
                var completion = context.getBean(SignInCompletionHandler.class);
                // The success handler asks the one completion bean; it builds none of its own.
                assertThat(ReflectionTestUtils.getField(context.getBean(SignInSuccessHandler.class), "completion")).isSameAs(completion);
                assertThat(ReflectionTestUtils.getField(completion, "gate")).isEqualTo(Optional.empty());
                assertThat(ReflectionTestUtils.getField(context.getBean(SignInFailureHandler.class), "gate")).isEqualTo(Optional.empty());
                assertThat(ReflectionTestUtils.getField(completion, "domainClient")).isSameAs(context.getBean("signInDomainClient"));
                assertThat(ReflectionTestUtils.getField(completion, "oauth")).isSameAs(OAUTH);
            });
        }
    }

    @Test void whereTheDevGateExistsTheCompletionAndTheFailureHandlerReceiveThatOne() {
        DevAccessGate gate = (request, user) -> { };
        runner.withBean(DevAccessGate.class, () -> gate)
                .withPropertyValues("spring.profiles.active=gateway,lower-cost-dev", "app.deployment-environment=dev",
                        DevServiceOrigins.DOMAIN_PROPERTY + "=" + DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB_PROPERTY + "=" + DevServiceOrigins.WEB)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(SignInCompletionHandler.class).hasSingleBean(SignInFailureHandler.class);
                    assertThat(ReflectionTestUtils.getField(context.getBean(SignInCompletionHandler.class), "gate")).isEqualTo(Optional.of(gate));
                    assertThat(ReflectionTestUtils.getField(context.getBean(SignInFailureHandler.class), "gate")).isEqualTo(Optional.of(gate));
                });
    }

    @Test void outsideTheGatewayProfileTheChainReceivesNothingFromHere() {
        runner.withPropertyValues("spring.profiles.active=accounts", "app.deployment-environment=local").run(context ->
                assertThat(context).hasNotFailed().doesNotHaveBean(SignInCompletionHandler.class).doesNotHaveBean(SignInSuccessHandler.class)
                        .doesNotHaveBean(SignInFailureHandler.class).doesNotHaveBean(FramePolicyHeaderWriter.class)
                        .doesNotHaveBean(DevWebAuthorizationManager.class));
    }
}
