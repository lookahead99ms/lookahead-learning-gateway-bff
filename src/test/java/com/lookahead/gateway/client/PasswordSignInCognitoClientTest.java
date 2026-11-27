package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.util.PasswordSignInAnswer;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.assertj.core.groups.Tuple;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.utils.builder.SdkBuilder;

/**
 * DLV-1015: what the client of our own sign-in pages hands back. No type of the Cognito SDK leaves it: an answer is a
 * {@code Step}, the tokens or the next step under Cognito's name, or the delivery destination; a refusal is
 * {@code Refused}. The requests it sends are also asserted through the routes in PasswordSignInHandlerTest; every test
 * of that class goes through a route, so none could move here, and the SECRET_HASH is computed on its own below.
 */
class PasswordSignInCognitoClientTest {
    static final String PASSWORD = "Synthetic-Passw0rd!x";
    final OAuthClientDetails oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    final List<Object> calls = new ArrayList<>();
    Function<String, Object> answer = method -> { throw new IllegalStateException("No fixture for " + method); };

    final CognitoIdentityProviderClient cognito = (CognitoIdentityProviderClient) Proxy.newProxyInstance(CognitoIdentityProviderClient.class.getClassLoader(),
        new Class<?>[]{CognitoIdentityProviderClient.class}, (proxy, method, args) -> {
            calls.add(built(method.getName(), args[0]));
            return answer.apply(method.getName());
        });
    final PasswordSignInCognitoClient client = new PasswordSignInCognitoClient(cognito, oauth);

    /** The SDK's consumer-builder overloads hand us a builder consumer; build the request so tests can read it. */
    static Object built(String method, Object argument) {
        Object builder = switch (method) {
            case "initiateAuth" -> InitiateAuthRequest.builder();
            case "respondToAuthChallenge" -> RespondToAuthChallengeRequest.builder();
            case "signUp" -> SignUpRequest.builder();
            case "confirmSignUp" -> ConfirmSignUpRequest.builder();
            case "resendConfirmationCode" -> ResendConfirmationCodeRequest.builder();
            case "forgotPassword" -> ForgotPasswordRequest.builder();
            case "confirmForgotPassword" -> ConfirmForgotPasswordRequest.builder();
            default -> throw new IllegalStateException(method);
        };
        @SuppressWarnings("unchecked") var accept = (Consumer<Object>) argument;
        accept.accept(builder);
        return ((SdkBuilder<?, ?>) builder).build();
    }

    static AuthenticationResultType tokens() {
        return AuthenticationResultType.builder().idToken("synthetic-id").accessToken("synthetic-access").refreshToken("synthetic-refresh").expiresIn(300).tokenType("Bearer").build();
    }

    static Supplier<String> never(String what) { return () -> { throw new AssertionError(what + " is not asked for"); }; }

    @Test void aSignInHandsBackTheTokensOrTheNextStepUnderCognitosName() {
        try (var log = new LogCapture("lookahead.upstream")) {
            answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
            var signedIn = client.signIn("priya@example.invalid", PASSWORD);
            assertThat(signedIn).isEqualTo(new PasswordSignInCognitoClient.Step(
                new PasswordSignInCognitoClient.Tokens("synthetic-id", "synthetic-access", "synthetic-refresh", 300), null, null));
            var sent = (InitiateAuthRequest) calls.getFirst();
            assertThat(sent.authFlow()).isEqualTo(AuthFlowType.USER_PASSWORD_AUTH);
            assertThat(sent.clientId()).isEqualTo(oauth.clientId());
            assertThat(sent.authParameters()).isEqualTo(Map.of("USERNAME", "priya@example.invalid", "PASSWORD", PASSWORD, "SECRET_HASH", client.secretHash("priya@example.invalid")));
            assertThat(log.messages()).hasSize(1).first().asString().matches("Upstream cognito InitiateAuth succeeded in \\d+ ms");
            // What Cognito left out stays out: no expiry, no refresh token.
            answer = m -> InitiateAuthResponse.builder().authenticationResult(AuthenticationResultType.builder().idToken("i").accessToken("a").build()).build();
            assertThat(client.signIn("priya@example.invalid", PASSWORD).tokens()).isEqualTo(new PasswordSignInCognitoClient.Tokens("i", "a", null, null));
            // A next step: Cognito's own name for it and the session string that answers it.
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).session("synthetic-cognito-session").build();
            assertThat(client.signIn("priya@example.invalid", PASSWORD)).isEqualTo(new PasswordSignInCognitoClient.Step(null, "EMAIL_OTP", "synthetic-cognito-session"));
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SMS_MFA).build();
            assertThat(client.signIn("priya@example.invalid", PASSWORD)).isEqualTo(new PasswordSignInCognitoClient.Step(null, "SMS_MFA", null));
            // A name this SDK version does not know reads as the text "null", as the SDK's own value prints it.
            answer = m -> InitiateAuthResponse.builder().challengeName("A_FUTURE_STEP").session("s").build();
            assertThat(client.signIn("priya@example.invalid", PASSWORD)).isEqualTo(new PasswordSignInCognitoClient.Step(null, "null", "s"));
            // Neither tokens nor a step.
            answer = m -> InitiateAuthResponse.builder().build();
            assertThat(client.signIn("priya@example.invalid", PASSWORD)).isEqualTo(new PasswordSignInCognitoClient.Step(null, null, null));
        }
    }

    @Test void aStepIsAnsweredUnderCognitosParameterNameWithOnlyTheValueItNeeds() {
        answer = m -> RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
        var done = client.respond("NEW_PASSWORD_REQUIRED", "synthetic-cognito-session", "arjun@example.invalid", () -> PASSWORD, never("the code"));
        assertThat(done.tokens().accessToken()).isEqualTo("synthetic-access");
        assertThat(done.stepName()).isNull();
        var sent = (RespondToAuthChallengeRequest) calls.getFirst();
        assertThat(sent.challengeName()).isEqualTo(ChallengeNameType.NEW_PASSWORD_REQUIRED);
        assertThat(sent.clientId()).isEqualTo(oauth.clientId());
        assertThat(sent.session()).isEqualTo("synthetic-cognito-session");
        assertThat(sent.challengeResponses()).isEqualTo(Map.of("NEW_PASSWORD", PASSWORD, "USERNAME", "arjun@example.invalid", "SECRET_HASH", client.secretHash("arjun@example.invalid")));
        for (var pair : List.of(List.of("SOFTWARE_TOKEN_MFA", "SOFTWARE_TOKEN_MFA_CODE"), List.of("EMAIL_OTP", "EMAIL_OTP_CODE"))) {
            calls.clear();
            answer = m -> RespondToAuthChallengeResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).session("the-next-session").build();
            assertThat(client.respond(pair.get(0), "s", "arjun@example.invalid", never("the new password"), () -> "123456"))
                .isEqualTo(new PasswordSignInCognitoClient.Step(null, "EMAIL_OTP", "the-next-session"));
            var code = (RespondToAuthChallengeRequest) calls.getFirst();
            assertThat(code.challengeNameAsString()).isEqualTo(pair.get(0));
            assertThat(code.challengeResponses()).isEqualTo(Map.of(pair.get(1), "123456", "USERNAME", "arjun@example.invalid", "SECRET_HASH", client.secretHash("arjun@example.invalid")));
        }
        // A step the page does not answer is refused before Cognito is called, and neither value is asked for.
        calls.clear();
        for (String kind : new String[] {"SMS_MFA", "SELECT_MFA_TYPE", "A_FUTURE_STEP", "null", "", "email_otp"})
            assertThatThrownBy(() -> client.respond(kind, "s", "arjun@example.invalid", never("the new password"), never("the code")))
                .as(kind).isExactlyInstanceOf(IllegalArgumentException.class).hasMessage("Unsupported challenge");
        assertThatThrownBy(() -> client.respond(null, "s", "arjun@example.invalid", never("the new password"), never("the code"))).isInstanceOf(NullPointerException.class);
        // A value that fails its own check leaves as it is, also before Cognito is called.
        var invalid = new IllegalArgumentException("code");
        assertThatThrownBy(() -> client.respond("EMAIL_OTP", "s", "arjun@example.invalid", never("the new password"), () -> { throw invalid; })).isSameAs(invalid);
        assertThat(calls).isEmpty();
    }

    @Test void signUpResendAndForgotHandBackTheAddressCognitoNamesOrNone() {
        var details = new LinkedHashMap<String, CodeDeliveryDetailsType>();
        details.put("p***@e***", CodeDeliveryDetailsType.builder().destination("p***@e***").deliveryMedium("EMAIL").build());
        details.put("  ", CodeDeliveryDetailsType.builder().destination("  ").build());
        var named = new ArrayList<String>();
        for (var given : List.of(details.get("p***@e***"), details.get("  "), CodeDeliveryDetailsType.builder().build())) {
            answer = m -> switch (m) {
                case "signUp" -> SignUpResponse.builder().codeDeliveryDetails(given).build();
                case "resendConfirmationCode" -> ResendConfirmationCodeResponse.builder().codeDeliveryDetails(given).build();
                default -> ForgotPasswordResponse.builder().codeDeliveryDetails(given).build();
            };
            assertThat(client.signUp("priya@example.invalid", PASSWORD, "Priya", "Rao")).isEqualTo(given.destination());
            assertThat(client.resend("priya@example.invalid")).isEqualTo(given.destination());
            assertThat(client.forgot("priya@example.invalid")).isEqualTo(given.destination());
            named.add(given.destination());
        }
        assertThat(named).containsExactly("p***@e***", "  ", null);
        // No delivery details at all.
        answer = m -> switch (m) {
            case "signUp" -> SignUpResponse.builder().build();
            case "resendConfirmationCode" -> ResendConfirmationCodeResponse.builder().build();
            default -> ForgotPasswordResponse.builder().build();
        };
        assertThat(client.signUp("priya@example.invalid", PASSWORD, "Priya", "Rao")).isNull();
        assertThat(client.resend("priya@example.invalid")).isNull();
        assertThat(client.forgot("priya@example.invalid")).isNull();
        // DLV-1015 (from PasswordSignInAnswerTest): the page is shown Cognito's own destination, else the masked email.
        assertThat(PasswordSignInAnswer.destination(named.get(0), "priya@example.invalid")).isEqualTo("p***@e***");
        assertThat(PasswordSignInAnswer.destination(client.forgot("priya@example.invalid"), "priya@example.invalid")).isEqualTo("p***@example.invalid");
        assertThat(PasswordSignInAnswer.destination(named.get(2), "priya@example.invalid")).isEqualTo("p***@example.invalid");
        assertThat(PasswordSignInAnswer.destination(named.get(1), "priya@example.invalid")).isEqualTo("p***@example.invalid");
        // What was sent.
        calls.clear();
        answer = m -> SignUpResponse.builder().build();
        client.signUp("arjun@example.invalid", PASSWORD, "Arjun", "Rao");
        var signUp = (SignUpRequest) calls.getFirst();
        assertThat(signUp.clientId()).isEqualTo(oauth.clientId());
        assertThat(signUp.username()).isEqualTo("arjun@example.invalid");
        assertThat(signUp.password()).isEqualTo(PASSWORD);
        assertThat(signUp.secretHash()).isEqualTo(client.secretHash("arjun@example.invalid"));
        assertThat(signUp.userAttributes()).extracting(AttributeType::name, AttributeType::value).containsExactly(
            Tuple.tuple("email", "arjun@example.invalid"), Tuple.tuple("given_name", "Arjun"),
            Tuple.tuple("family_name", "Rao"), Tuple.tuple("name", "Arjun Rao"));
    }

    @Test void confirmAndResetSendTheCodeAndAnswerNothing() {
        answer = m -> m.equals("confirmSignUp") ? ConfirmSignUpResponse.builder().build() : ConfirmForgotPasswordResponse.builder().build();
        client.confirmSignUp("arjun@example.invalid", "123456");
        var confirm = (ConfirmSignUpRequest) calls.getFirst();
        assertThat(List.of(confirm.clientId(), confirm.username(), confirm.confirmationCode(), confirm.secretHash()))
            .containsExactly(oauth.clientId(), "arjun@example.invalid", "123456", client.secretHash("arjun@example.invalid"));
        client.reset("arjun@example.invalid", "654321", PASSWORD);
        var reset = (ConfirmForgotPasswordRequest) calls.get(1);
        assertThat(List.of(reset.clientId(), reset.username(), reset.confirmationCode(), reset.password(), reset.secretHash()))
            .containsExactly(oauth.clientId(), "arjun@example.invalid", "654321", PASSWORD, client.secretHash("arjun@example.invalid"));
    }

    /** Every operation of the client, as one call. */
    Map<String, Runnable> operations() {
        var all = new LinkedHashMap<String, Runnable>();
        all.put("InitiateAuth", () -> client.signIn("priya@example.invalid", PASSWORD));
        all.put("RespondToAuthChallenge", () -> client.respond("EMAIL_OTP", "s", "priya@example.invalid", never("the new password"), () -> "123456"));
        all.put("SignUp", () -> client.signUp("priya@example.invalid", PASSWORD, "Priya", "Rao"));
        all.put("ConfirmSignUp", () -> client.confirmSignUp("priya@example.invalid", "123456"));
        all.put("ResendConfirmationCode", () -> client.resend("priya@example.invalid"));
        all.put("ForgotPassword", () -> client.forgot("priya@example.invalid"));
        all.put("ConfirmForgotPassword", () -> client.reset("priya@example.invalid", "123456", PASSWORD));
        return all;
    }

    @Test void aRefusalByCognitoLeavesAsRefusedWithItsKindItsMessageAndTheAwsCode() {
        try (var log = new LogCapture("lookahead.upstream")) {
            var refusal = NotAuthorizedException.builder().message("Incorrect username or password.").statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("NotAuthorizedException").errorMessage("Incorrect username or password.").build()).build();
            answer = m -> { throw refusal; };
            operations().forEach((operation, call) -> {
                log.clear();
                var refused = catchThrowableOfType(PasswordSignInCognitoClient.Refused.class, call::run);
                assertThat(refused).as(operation).isNotNull();
                assertThat(refused.is("NotAuthorizedException")).isTrue();
                assertThat(refused.is("UserNotFoundException")).isFalse();
                assertThat(refused.is("CognitoIdentityProviderException")).isFalse();
                assertThat(refused.getMessage()).isEqualTo(refusal.getMessage()).contains("Incorrect username or password.");
                assertThat(refused.code()).isEqualTo("NotAuthorizedException");
                assertThat(refused.getCause()).isSameAs(refusal);
                // The upstream line of the call is written here, as before: the status and the code, never the message.
                assertThat(log.messages()).hasSize(1).first().asString().matches("Upstream cognito " + operation + " -> 400 NotAuthorizedException in \\d+ ms");
            });
        }
        // Without AWS error details, or with a code that is not one, the code is the name of the exception; a message may be absent.
        var bare = new PasswordSignInCognitoClient.Refused(TooManyRequestsException.builder().build());
        assertThat(bare.is("TooManyRequestsException")).isTrue();
        assertThat(bare.code()).isEqualTo("TooManyRequestsException");
        assertThat(bare.getMessage()).isNull();
        var odd = new PasswordSignInCognitoClient.Refused(LimitExceededException.builder().message("Attempt limit exceeded")
            .awsErrorDetails(AwsErrorDetails.builder().errorCode("not a code!").build()).build());
        assertThat(odd.code()).isEqualTo("LimitExceededException");
        // A refusal without a type of its own keeps the code Cognito sent; it is of no named kind.
        var general = new PasswordSignInCognitoClient.Refused((CognitoIdentityProviderException) CognitoIdentityProviderException.builder().message("Rate exceeded")
            .awsErrorDetails(AwsErrorDetails.builder().errorCode("ThrottlingException").build()).build());
        assertThat(general.code()).isEqualTo("ThrottlingException");
        assertThat(general.is("CognitoIdentityProviderException")).isTrue();
        assertThat(general.is("ThrottlingException")).isFalse();
    }

    @Test void anyOtherFailureLeavesAsItIs() {
        for (RuntimeException failure : List.of(new IllegalStateException("synthetic transport failure"), new IllegalArgumentException("synthetic"),
                SdkClientException.builder().message("Unable to execute HTTP request").build(),
                AwsServiceException.builder().message("not Cognito's").statusCode(500).build())) {
            answer = m -> { throw failure; };
            operations().forEach((operation, call) -> assertThatThrownBy(call::run).as(operation).isSameAs(failure));
        }
    }

    /** Base64(HMAC-SHA256(client secret, username + client id)), computed here on its own and not by the client. */
    String hmac(String username) throws Exception {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(oauth.clientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal((username + oauth.clientId()).getBytes(StandardCharsets.UTF_8)));
    }

    /** DLV-1015: every one of the seven requests names the app client and carries the SECRET_HASH of its own username. */
    @Test void everyRequestCarriesTheSecretHashOfItsOwnUsernameAndTheClientId() throws Exception {
        String priya = hmac("priya@example.invalid"), arjun = hmac("arjun@example.invalid");
        assertThat(client.secretHash("priya@example.invalid")).isEqualTo(priya).isNotEqualTo(arjun);
        assertThat(client.secretHash("arjun@example.invalid")).isEqualTo(arjun);
        // The hash is over the username exactly as it is given.
        assertThat(client.secretHash("Priya@example.invalid")).isEqualTo(hmac("Priya@example.invalid")).isNotEqualTo(priya);
        answer = m -> switch (m) {
            case "initiateAuth" -> InitiateAuthResponse.builder().build();
            case "respondToAuthChallenge" -> RespondToAuthChallengeResponse.builder().build();
            case "signUp" -> SignUpResponse.builder().build();
            case "confirmSignUp" -> ConfirmSignUpResponse.builder().build();
            case "resendConfirmationCode" -> ResendConfirmationCodeResponse.builder().build();
            case "forgotPassword" -> ForgotPasswordResponse.builder().build();
            default -> ConfirmForgotPasswordResponse.builder().build();
        };
        operations().values().forEach(Runnable::run);
        assertThat(calls).hasSize(7);
        var signIn = (InitiateAuthRequest) calls.get(0);
        assertThat(List.of(signIn.clientId(), signIn.authParameters().get("USERNAME"), signIn.authParameters().get("SECRET_HASH")))
            .containsExactly(oauth.clientId(), "priya@example.invalid", priya);
        var respond = (RespondToAuthChallengeRequest) calls.get(1);
        assertThat(List.of(respond.clientId(), respond.challengeResponses().get("USERNAME"), respond.challengeResponses().get("SECRET_HASH")))
            .containsExactly(oauth.clientId(), "priya@example.invalid", priya);
        var signUp = (SignUpRequest) calls.get(2);
        assertThat(List.of(signUp.clientId(), signUp.username(), signUp.secretHash())).containsExactly(oauth.clientId(), "priya@example.invalid", priya);
        var confirm = (ConfirmSignUpRequest) calls.get(3);
        assertThat(List.of(confirm.clientId(), confirm.username(), confirm.secretHash())).containsExactly(oauth.clientId(), "priya@example.invalid", priya);
        // The two requests that carry nothing but the app client, the username and the hash.
        var resend = (ResendConfirmationCodeRequest) calls.get(4);
        assertThat(resend).isEqualTo(ResendConfirmationCodeRequest.builder().clientId(oauth.clientId()).username("priya@example.invalid").secretHash(priya).build());
        var forgot = (ForgotPasswordRequest) calls.get(5);
        assertThat(forgot).isEqualTo(ForgotPasswordRequest.builder().clientId(oauth.clientId()).username("priya@example.invalid").secretHash(priya).build());
        var reset = (ConfirmForgotPasswordRequest) calls.get(6);
        assertThat(List.of(reset.clientId(), reset.username(), reset.secretHash())).containsExactly(oauth.clientId(), "priya@example.invalid", priya);
    }

    @Test void tokensAndTheSessionStringAreNeverPrinted() {
        var tokens = new PasswordSignInCognitoClient.Tokens("synthetic-id", "synthetic-access", "synthetic-refresh", 300);
        assertThat(tokens.toString()).isEqualTo("Tokens[not shown]");
        assertThat(new PasswordSignInCognitoClient.Step(tokens, null, null).toString()).isEqualTo("Step[tokens]");
        assertThat(new PasswordSignInCognitoClient.Step(null, "EMAIL_OTP", "synthetic-cognito-session").toString()).isEqualTo("Step[EMAIL_OTP]");
        assertThat(new PasswordSignInCognitoClient.Step(null, null, null).toString()).isEqualTo("Step[null]");
    }
}
