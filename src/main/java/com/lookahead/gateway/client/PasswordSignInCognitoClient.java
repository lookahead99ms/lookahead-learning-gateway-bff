package com.lookahead.gateway.client;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Supplier;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

/**
 * DLV-969: the Cognito user-pool calls behind our own sign-in and sign-up pages. Every call is one of Cognito's
 * unauthenticated client operations (client id plus SECRET_HASH), so no IAM permission is involved. Passwords and codes
 * pass straight through to Cognito; nothing here stores or logs them. Each call writes one {@code lookahead.upstream} line
 * (operation, outcome, time, and Cognito's error code and HTTP status when it refuses), never the message.
 *
 * <p>No type of the Cognito SDK leaves this class: an answer leaves as {@link Step} or as the delivery destination, a
 * refusal as {@link Refused}.
 */
public final class PasswordSignInCognitoClient {
    private final CognitoIdentityProviderClient cognito;
    private final OAuthClientDetails oauth;

    public PasswordSignInCognitoClient(CognitoIdentityProviderClient cognito, OAuthClientDetails oauth) { this.cognito = cognito; this.oauth = oauth; }

    /** The tokens of a completed sign-in, as Cognito returned them. They are secrets: never printed. */
    public record Tokens(String idToken, String accessToken, String refreshToken, Integer expiresIn) {
        @Override public String toString() { return "Tokens[not shown]"; }
    }

    /**
     * Cognito's answer to a sign-in or to a sign-in step: the tokens, or the next step under Cognito's own name
     * ({@code EMAIL_OTP}; the text {@code null} for a name this SDK version does not know) with the session string that
     * answers it. An answer that is neither has no tokens and no challenge. The session string is a secret: never printed.
     */
    // stepName: Cognito's name for the next sign-in step (NEW_PASSWORD_REQUIRED, SOFTWARE_TOKEN_MFA, EMAIL_OTP...), never a secret.
    public record Step(Tokens tokens, String stepName, String session) {
        @Override public String toString() { return "Step[" + (tokens != null ? "tokens" : stepName) + "]"; }
    }

    /**
     * Cognito refused the call. Carries what the page's answer and its log line are made of: the name of Cognito's
     * exception, its message, and the AWS error code as {@code OpsLog.awsCode} reads it.
     */
    public static final class Refused extends RuntimeException {
        private final String kind, code;

        public Refused(CognitoIdentityProviderException rejected) {
            super(rejected.getMessage(), rejected);
            this.kind = rejected.getClass().getSimpleName();
            this.code = OpsLog.awsCode(rejected);
        }

        /** True for a refusal of this kind, by the simple name of Cognito's exception: {@code NotAuthorizedException}. */
        public boolean is(String name) { return kind.equals(name); }

        public String code() { return code; }
    }

    /** Runs one call; a refusal by Cognito leaves as {@link Refused}, any other failure as it is. */
    private static <T> T refusable(Supplier<T> call) {
        try {
            return call.get();
        } catch (CognitoIdentityProviderException rejected) {
            throw new Refused(rejected);
        }
    }

    private static Step step(ChallengeNameType stepType, String session, AuthenticationResultType tokens) {
        return new Step(tokens == null ? null : new Tokens(tokens.idToken(), tokens.accessToken(), tokens.refreshToken(), tokens.expiresIn()),
            stepType == null ? null : stepType.toString(), session);
    }

    /** The address Cognito says the code went to; null when it names none. */
    private static String destination(CodeDeliveryDetailsType details) { return details == null ? null : details.destination(); }

    /** The user pool app client the calls name, for the ERROR line when Cognito refuses or does not answer. */
    private String resource() { return "app client " + oauth.clientId(); }

    /** Base64(HMAC-SHA256(client secret, username + client id)), as Cognito requires for a client with a secret. */
    String secretHash(String username) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(oauth.clientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal((username + oauth.clientId()).getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException impossible) {
            throw new IllegalStateException("HmacSHA256 unavailable", impossible);
        }
    }

    public Step signIn(String username, String password) {
        var result = refusable(() -> OpsLog.aws("cognito", "InitiateAuth", resource(), false, () -> cognito.initiateAuth(r -> r.clientId(oauth.clientId()).authFlow(AuthFlowType.USER_PASSWORD_AUTH)
            .authParameters(Map.of("USERNAME", username, "PASSWORD", password, "SECRET_HASH", secretHash(username))))));
        return step(result.challengeName(), result.session(), result.authenticationResult());
    }

    /**
     * Answers the sign-in step {@code kind} (Cognito's own name for it). Each step is answered by one value, the new
     * password or the code, under the parameter name Cognito expects; only the value the step needs is asked for, and
     * a step this page does not answer is an {@link IllegalArgumentException} before Cognito is called.
     */
    public Step respond(String kind, String session, String username, Supplier<String> newPassword, Supplier<String> code) {
        var challenge = ChallengeNameType.fromValue(kind);
        Map<String, String> answers = switch (challenge) {
            case NEW_PASSWORD_REQUIRED -> Map.of("NEW_PASSWORD", newPassword.get());
            case SOFTWARE_TOKEN_MFA -> Map.of("SOFTWARE_TOKEN_MFA_CODE", code.get());
            case EMAIL_OTP -> Map.of("EMAIL_OTP_CODE", code.get());
            default -> throw new IllegalArgumentException("Unsupported challenge");
        };
        var responses = new HashMap<>(answers);
        responses.put("USERNAME", username);
        responses.put("SECRET_HASH", secretHash(username));
        var result = refusable(() -> OpsLog.aws("cognito", "RespondToAuthChallenge", resource(), false, () -> cognito.respondToAuthChallenge(r -> r.clientId(oauth.clientId())
            .challengeName(challenge).session(session).challengeResponses(responses))));
        return step(result.challengeName(), result.session(), result.authenticationResult());
    }

    /** Returns the address Cognito says the confirmation code went to, or null. */
    public String signUp(String email, String password, String firstName, String lastName) {
        var result = refusable(() -> OpsLog.aws("cognito", "SignUp", resource(), false, () -> cognito.signUp(r -> r.clientId(oauth.clientId()).username(email).password(password).secretHash(secretHash(email))
            .userAttributes(attribute("email", email), attribute("given_name", firstName), attribute("family_name", lastName),
                attribute("name", (firstName + " " + lastName).strip())))));
        return destination(result.codeDeliveryDetails());
    }

    public void confirmSignUp(String email, String code) {
        refusable(() -> OpsLog.aws("cognito", "ConfirmSignUp", resource(), false, () -> cognito.confirmSignUp(r -> r.clientId(oauth.clientId()).username(email).confirmationCode(code).secretHash(secretHash(email)))));
    }

    /** Returns the address Cognito says the confirmation code went to, or null. */
    public String resend(String email) {
        var result = refusable(() -> OpsLog.aws("cognito", "ResendConfirmationCode", resource(), false, () -> cognito.resendConfirmationCode(r -> r.clientId(oauth.clientId()).username(email).secretHash(secretHash(email)))));
        return destination(result.codeDeliveryDetails());
    }

    /** Returns the address Cognito says the reset code went to, or null. */
    public String forgot(String email) {
        var result = refusable(() -> OpsLog.aws("cognito", "ForgotPassword", resource(), false, () -> cognito.forgotPassword(r -> r.clientId(oauth.clientId()).username(email).secretHash(secretHash(email)))));
        return destination(result.codeDeliveryDetails());
    }

    public void reset(String email, String code, String newPassword) {
        refusable(() -> OpsLog.aws("cognito", "ConfirmForgotPassword", resource(), false, () -> cognito.confirmForgotPassword(r -> r.clientId(oauth.clientId()).username(email).confirmationCode(code).password(newPassword).secretHash(secretHash(email)))));
    }

    private static AttributeType attribute(String name, String value) { return AttributeType.builder().name(name).value(value).build(); }
}
