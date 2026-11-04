package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

/**
 * DLV-969: the Cognito user-pool calls behind our own sign-in and sign-up pages. Every call is one of Cognito's
 * unauthenticated client operations (client id plus SECRET_HASH), so no IAM permission is involved. Passwords and codes
 * pass straight through to Cognito; nothing here stores or logs them. Each call writes one {@code lookahead.upstream} line
 * (operation, outcome, time, and Cognito's error code and HTTP status when it refuses), never the message.
 */
final class CognitoPasswordClient {
    private final CognitoIdentityProviderClient cognito;
    private final OAuthSettings settings;

    CognitoPasswordClient(CognitoIdentityProviderClient cognito, OAuthSettings settings) { this.cognito = cognito; this.settings = settings; }

    /** Base64(HMAC-SHA256(client secret, username + client id)), as Cognito requires for a client with a secret. */
    String secretHash(String username) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(settings.clientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return Base64.getEncoder().encodeToString(mac.doFinal((username + settings.clientId()).getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.GeneralSecurityException impossible) {
            throw new IllegalStateException("HmacSHA256 unavailable", impossible);
        }
    }

    InitiateAuthResponse signIn(String username, String password) {
        return OpsLog.aws("cognito", "InitiateAuth", () -> cognito.initiateAuth(r -> r.clientId(settings.clientId()).authFlow(AuthFlowType.USER_PASSWORD_AUTH)
            .authParameters(Map.of("USERNAME", username, "PASSWORD", password, "SECRET_HASH", secretHash(username)))));
    }

    RespondToAuthChallengeResponse respond(ChallengeNameType challenge, String session, String username, Map<String, String> answers) {
        var responses = new java.util.HashMap<>(answers);
        responses.put("USERNAME", username);
        responses.put("SECRET_HASH", secretHash(username));
        return OpsLog.aws("cognito", "RespondToAuthChallenge", () -> cognito.respondToAuthChallenge(r -> r.clientId(settings.clientId())
            .challengeName(challenge).session(session).challengeResponses(responses)));
    }

    SignUpResponse signUp(String email, String password, String firstName, String lastName) {
        return OpsLog.aws("cognito", "SignUp", () -> cognito.signUp(r -> r.clientId(settings.clientId()).username(email).password(password).secretHash(secretHash(email))
            .userAttributes(attribute("email", email), attribute("given_name", firstName), attribute("family_name", lastName),
                attribute("name", (firstName + " " + lastName).strip()))));
    }

    void confirmSignUp(String email, String code) {
        OpsLog.aws("cognito", "ConfirmSignUp", () -> cognito.confirmSignUp(r -> r.clientId(settings.clientId()).username(email).confirmationCode(code).secretHash(secretHash(email))));
    }

    ResendConfirmationCodeResponse resend(String email) {
        return OpsLog.aws("cognito", "ResendConfirmationCode", () -> cognito.resendConfirmationCode(r -> r.clientId(settings.clientId()).username(email).secretHash(secretHash(email))));
    }

    ForgotPasswordResponse forgot(String email) {
        return OpsLog.aws("cognito", "ForgotPassword", () -> cognito.forgotPassword(r -> r.clientId(settings.clientId()).username(email).secretHash(secretHash(email))));
    }

    void reset(String email, String code, String newPassword) {
        OpsLog.aws("cognito", "ConfirmForgotPassword", () -> cognito.confirmForgotPassword(r -> r.clientId(settings.clientId()).username(email).confirmationCode(code).password(newPassword).secretHash(secretHash(email))));
    }

    private static AttributeType attribute(String name, String value) { return AttributeType.builder().name(name).value(value).build(); }
}
