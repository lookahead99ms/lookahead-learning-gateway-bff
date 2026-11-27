package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.lookahead.gateway.client.PasswordSignInCognitoClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.log.OpsLogTest;
import com.lookahead.gateway.security.config.OAuthClientConfiguration;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.session.PasswordSignInSession;
import com.lookahead.gateway.util.AccountMergeOffer;
import com.lookahead.gateway.util.PasswordSignInAnswer;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import software.amazon.awssdk.awscore.exception.AwsErrorDetails;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import jakarta.servlet.http.HttpServletRequest;
import java.time.ZoneId;
import java.util.LinkedHashMap;
import java.util.function.Consumer;
import org.assertj.core.groups.Tuple;
import org.mockito.ArgumentMatchers;
import software.amazon.awssdk.utils.builder.SdkBuilder;

/**
 * DLV-969: our own email-and-password pages, with Cognito behind each route. DLV-1015: what the routes do lives in
 * PasswordSignInHandler, so these tests moved here from PasswordSignInControllerTest, with the tests of the route
 * runner, the error mapping and the outcome line (from PasswordSignInAnswerTest) and of the step after Cognito's answer
 * (from PasswordSignInSessionTest).
 */
class PasswordSignInHandlerTest {
    static final String PASSWORD = "Synthetic-Passw0rd!x";
    final OAuthClientDetails oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    final ClientRegistrationRepository registrations = new OAuthClientConfiguration().oauthClientRegistrations(oauth);
    final HttpSessionOAuth2AuthorizedClientRepository clients = new HttpSessionOAuth2AuthorizedClientRepository();
    final SignInCompletionHandler completion = mock(SignInCompletionHandler.class);
    final MutableClock clock = new MutableClock(Instant.parse("2026-11-02T20:00:00Z"));
    final List<Object> calls = new ArrayList<>();
    Function<String, Object> answer = method -> { throw new IllegalStateException("No fixture for " + method); };
    String tokenUse = "id";

    final CognitoIdentityProviderClient cognito = (CognitoIdentityProviderClient) Proxy.newProxyInstance(CognitoIdentityProviderClient.class.getClassLoader(),
        new Class<?>[]{CognitoIdentityProviderClient.class}, (proxy, method, args) -> {
            switch (method.getName()) {
                case "close": return null;
                case "serviceName": return "cognito-idp";
                case "toString": return "fixture";
                case "hashCode": return 1;
                case "equals": return proxy == args[0];
                default: break;
            }
            calls.add(built(method.getName(), args[0]));
            return answer.apply(method.getName());
        });

    /** The SDK's consumer-builder overloads hand us a builder consumer; build the request so tests can read it. */
    static Object built(String method, Object argument) {
        if (!(argument instanceof Consumer<?> consumer)) return argument;
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
        @SuppressWarnings("unchecked") var accept = (Consumer<Object>) consumer;
        accept.accept(builder);
        return ((SdkBuilder<?, ?>) builder).build();
    }

    final JwtDecoderFactory<ClientRegistration> idDecoders = registration -> token -> Jwt.withTokenValue(token).header("alg", "RS256")
        .issuer(oauth.issuer()).subject("synthetic-subject").audience(List.of(oauth.clientId()))
        .issuedAt(clock.instant()).expiresAt(clock.instant().plusSeconds(300)).claim("auth_time", clock.instant())
        .claim("token_use", tokenUse).claim("cognito:username", "priya@example.invalid").build();

    PasswordSignInHandler handler() {
        return new PasswordSignInHandler(new PasswordSignInCognitoClient(cognito, oauth), new PasswordSignInThrottle(clock),
            new PasswordSignInSession(registrations, idDecoders, clients, completion, clock));
    }
    PasswordSignInHandler handler = handler();

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    static MockHttpServletRequest post(String json) {
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/x");
        request.setContent(json.getBytes(StandardCharsets.UTF_8)); request.setContentType("application/json"); request.setRemoteAddr("203.0.113.9");
        return request;
    }
    static Map<?, ?> data(ResponseEntity<?> response) {
        return (Map<?, ?>) ((ApiResponse<?>) response.getBody()).data();
    }
    static String code(ResponseEntity<?> response) { return (String) ((Map<?, ?>) response.getBody()).get("code"); }
    static AuthenticationResultType tokens() {
        return AuthenticationResultType.builder().idToken("synthetic-id").accessToken("synthetic-access").refreshToken("synthetic-refresh").expiresIn(300).tokenType("Bearer").build();
    }
    String secretHash(String username) throws Exception {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(oauth.clientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal((username + oauth.clientId()).getBytes(StandardCharsets.UTF_8)));
    }

    @Test void signInBuildsTheOAuthEquivalentSessionAndFinishesThroughTheSharedPath() throws Exception {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        when(completion.completeSignIn(any(), any(), any())).thenReturn("/learn");
        var request = post("{\"email\":\" Priya@Example.invalid \",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}");
        request.getSession(true); String before = request.getSession().getId();
        var response = handler.signIn(request, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(data(response)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
        var sent = (InitiateAuthRequest) calls.getFirst();
        assertThat(sent.authFlow()).isEqualTo(AuthFlowType.USER_PASSWORD_AUTH);
        assertThat(sent.clientId()).isEqualTo(oauth.clientId());
        assertThat(sent.authParameters()).containsEntry("USERNAME", "priya@example.invalid").containsEntry("PASSWORD", PASSWORD)
            .containsEntry("SECRET_HASH", secretHash("priya@example.invalid"));
        var session = request.getSession(false);
        assertThat(request.getSession().getId()).isNotEqualTo(before);
        assertThat(session.getAttribute("learningReturnTo")).isEqualTo("/learn");
        var context = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
        var authentication = (OAuth2AuthenticationToken) context.getAuthentication();
        assertThat(authentication.getAuthorizedClientRegistrationId()).isEqualTo("lookahead");
        assertThat(((OidcUser) authentication.getPrincipal()).getSubject()).isEqualTo("synthetic-subject");
        assertThat(((OidcUser) authentication.getPrincipal()).getIdToken().getTokenValue()).isEqualTo("synthetic-id");
        OAuth2AuthorizedClient client = clients.loadAuthorizedClient("lookahead", authentication, request);
        assertThat(client.getAccessToken().getTokenValue()).isEqualTo("synthetic-access");
        assertThat(client.getAccessToken().getExpiresAt()).isEqualTo(clock.instant().plusSeconds(300));
        assertThat(client.getRefreshToken().getTokenValue()).isEqualTo("synthetic-refresh");
        verify(completion).completeSignIn(ArgumentMatchers.same(request), any(), ArgumentMatchers.eq(authentication));
        // The browser never sees a token.
        assertThat(response.getBody().toString()).doesNotContain("synthetic-access", "synthetic-refresh", "synthetic-id", PASSWORD);
    }

    /** DLV-969 S36: SIGNED_IN carries mergeAvailable only when the shared completion saw Domain's literal true; next stays normal. */
    @Test void signedInCarriesMergeAvailableOnlyWhenDomainSaidTrue() {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        when(completion.completeSignIn(any(), any(), any())).thenAnswer(call -> {
            ((HttpServletRequest) call.getArgument(0)).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
            return "/learn";
        });
        var merge = handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(merge)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
        // No attribute (Domain sent false, nothing, or a non-boolean): the field is absent.
        doReturn("/learn").when(completion).completeSignIn(any(), any(), any());
        var plain = handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(plain)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
        // Only Boolean.TRUE counts as the marker.
        doAnswer(call -> {
            ((HttpServletRequest) call.getArgument(0)).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, "true");
            return "/learn";
        }).when(completion).completeSignIn(any(), any(), any());
        var text = handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(text)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
    }

    /** DLV-969 S36: the flag rides only on a final destination; the challenge and reset routes' final SIGNED_IN carry it too. */
    @Test void mergeAvailableOnlyRidesOnAFinalDestination() {
        String[] next = {"/learn"};
        doAnswer(call -> {
            ((HttpServletRequest) call.getArgument(0)).setAttribute(AccountMergeOffer.MERGE_AVAILABLE, Boolean.TRUE);
            return next[0];
        }).when(completion).completeSignIn(any(), any(), any());
        // A further sign-in step or a refusal page is never a final destination.
        for (String step : new String[] {"/sign-in/choose?returnTo=%2Flearn", "/sign-in?error=admission", "/welcome?access=pending", "/dev/access?error=signin"}) {
            next[0] = step;
            answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
            var response = handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(data(response)).as(step).isEqualTo(Map.of("step", "SIGNED_IN", "next", step));
        }
        next[0] = "/learn";
        // The email-code challenge, once answered, is the final sign-in.
        answer = m -> m.equals("initiateAuth")
            ? InitiateAuthResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).session("s").build()
            : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
        var first = post("{\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(data(handler.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "EMAIL_CODE"));
        var code = post("{\"code\":\"123456\"}"); code.setSession(first.getSession());
        assertThat(data(handler.challenge(code, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
        // So is the sign-in that follows a password reset.
        answer = m -> m.equals("confirmForgotPassword") ? ConfirmForgotPasswordResponse.builder().build()
            : InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        var reset = handler.reset(post("{\"email\":\"meera@example.invalid\",\"code\":\"123456\",\"newPassword\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(reset)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
    }

    @Test void unsafeReturnFallsBackHomeAndMissingExpiryDefaultsToFiveMinutes() {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens().toBuilder().expiresIn(null).refreshToken(null).build()).build();
        when(completion.completeSignIn(any(), any(), any())).thenReturn("/");
        var request = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"https://evil.invalid/\"}");
        handler.signIn(request, new MockHttpServletResponse());
        assertThat(request.getSession().getAttribute("learningReturnTo")).isEqualTo("/");
        var context = (SecurityContext) request.getSession().getAttribute("SPRING_SECURITY_CONTEXT");
        OAuth2AuthorizedClient client = clients.loadAuthorizedClient("lookahead", context.getAuthentication(), request);
        assertThat(client.getAccessToken().getExpiresAt()).isEqualTo(clock.instant().plusSeconds(300));
        assertThat(client.getRefreshToken()).isNull();
    }

    @Test void aTokenThatIsNotAnIdTokenNeverBecomesASession() {
        tokenUse = "access";
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        var request = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
        var response = handler.signIn(request, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(request.getSession(false) == null || request.getSession().getAttribute("SPRING_SECURITY_CONTEXT") == null).isTrue();
        verifyNoInteractions(completion);
    }

    @Test void newPasswordChallengeIsAnsweredOnceWithinItsWindow() throws Exception {
        answer = m -> m.equals("initiateAuth")
            ? InitiateAuthResponse.builder().challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED).session("synthetic-session").build()
            : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
        when(completion.completeSignIn(any(), any(), any())).thenReturn("/");
        var first = post("{\"email\":\"arjun@example.invalid\",\"password\":\"Temporary-Passw0rd!\"}");
        assertThat(data(handler.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "NEW_PASSWORD"));
        var second = post("{\"newPassword\":\"" + PASSWORD + "\"}"); second.setSession(first.getSession());
        var done = handler.challenge(second, new MockHttpServletResponse());
        assertThat(data(done)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/"));
        var sent = (RespondToAuthChallengeRequest) calls.get(1);
        assertThat(sent.challengeName()).isEqualTo(ChallengeNameType.NEW_PASSWORD_REQUIRED);
        assertThat(sent.session()).isEqualTo("synthetic-session");
        assertThat(sent.challengeResponses()).containsEntry("NEW_PASSWORD", PASSWORD).containsEntry("USERNAME", "arjun@example.invalid")
            .containsEntry("SECRET_HASH", secretHash("arjun@example.invalid"));
        // The challenge cannot be replayed.
        var replay = post("{\"newPassword\":\"" + PASSWORD + "\"}"); replay.setSession(second.getSession());
        assertThat(code(handler.challenge(replay, new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
    }

    @Test void challengeWithoutPendingStateOrAfterThreeMinutesIsExpired() {
        assertThat(code(handler.challenge(post("{\"code\":\"123456\"}"), new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
        answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SOFTWARE_TOKEN_MFA).session("s").build();
        var first = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(data(handler.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "APP_CODE"));
        clock.advance(181);
        var late = post("{\"code\":\"123456\"}"); late.setSession(first.getSession());
        assertThat(code(handler.challenge(late, new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
        assertThat(first.getSession().getAttribute(PasswordSignInSession.PENDING)).isNull();
    }

    @Test void codeChallengesMapToAppAndEmailAndUnsupportedOnesFailClosed() {
        when(completion.completeSignIn(any(), any(), any())).thenReturn("/");
        for (var pair : List.of(List.of(ChallengeNameType.SOFTWARE_TOKEN_MFA, "APP_CODE", "SOFTWARE_TOKEN_MFA_CODE"), List.of(ChallengeNameType.EMAIL_OTP, "EMAIL_CODE", "EMAIL_OTP_CODE"))) {
            calls.clear();
            answer = m -> m.equals("initiateAuth")
                ? InitiateAuthResponse.builder().challengeName((ChallengeNameType) pair.get(0)).session("s").build()
                : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
            var first = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
            assertThat(data(handler.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", pair.get(1)));
            var bad = post("{\"code\":\"12ab56\"}"); bad.setSession(first.getSession());
            assertThat(code(handler.challenge(bad, new MockHttpServletResponse()))).isEqualTo("INVALID_REQUEST");
            var good = post("{\"code\":\"123456\"}"); good.setSession(first.getSession());
            assertThat(data(handler.challenge(good, new MockHttpServletResponse())).get("step")).isEqualTo("SIGNED_IN");
            assertThat(((RespondToAuthChallengeRequest) calls.get(1)).challengeResponses()).containsEntry((String) pair.get(2), "123456");
        }
        answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SMS_MFA).session("s").build();
        assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
        answer = m -> InitiateAuthResponse.builder().build();
        assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
    }

    /** DLV-969: an unsupported or incomplete Cognito step names the step; the page still only sees SERVICE_UNAVAILABLE. */
    @Test void anUnsupportedCognitoStepIsNamedInTheLog() {
        try (var log = new LogCapture("lookahead.event")) {
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SMS_MFA).session("synthetic-cognito-session").build();
            assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
            var step = log.lines().stream().filter(line -> "sign-in.cognito-step".equals(line.getKeyValuePairs().getFirst().value)).toList();
            assertThat(step).hasSize(1);
            assertThat(step.getFirst().getFormattedMessage()).startsWith("Cognito asked for sign-in step SMS_MFA: COGNITO_STEP_UNSUPPORTED (our sign-in page does not support it");
            assertThat(LogCapture.pairs(step.getFirst())).contains("reason=COGNITO_STEP_UNSUPPORTED", "cognito.challenge=SMS_MFA");
            log.clear();
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).build();
            assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
            assertThat(log.messages()).contains("Cognito's sign-in answer was incomplete: COGNITO_ANSWER_INCOMPLETE (no tokens and no session for step EMAIL_OTP); answered 503");
            log.clear();
            answer = m -> InitiateAuthResponse.builder().build();
            handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(log.messages()).contains("Cognito's sign-in answer was incomplete: COGNITO_ANSWER_INCOMPLETE (no tokens and no next step); answered 503");
            log.assertNothing(PASSWORD, "synthetic-cognito-session", "priya");
        }
    }

    @Test void signUpConfirmResendForgotAndReset() throws Exception {
        answer = m -> switch (m) {
            case "signUp" -> SignUpResponse.builder().codeDeliveryDetails(CodeDeliveryDetailsType.builder().destination("a***@e***").build()).build();
            case "confirmSignUp" -> ConfirmSignUpResponse.builder().build();
            case "resendConfirmationCode" -> ResendConfirmationCodeResponse.builder().codeDeliveryDetails(CodeDeliveryDetailsType.builder().destination("a***@e***").build()).build();
            case "forgotPassword" -> ForgotPasswordResponse.builder().build();
            case "confirmForgotPassword" -> ConfirmForgotPasswordResponse.builder().build();
            default -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        };
        when(completion.completeSignIn(any(), any(), any())).thenReturn("/?access=pending");
        assertThat(data(handler.signUp(post("{\"firstName\":\" Arjun \",\"lastName\":\"Rao\",\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/\"}"))))
            .isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@e***"));
        var signUp = (SignUpRequest) calls.getFirst();
        assertThat(signUp.username()).isEqualTo("arjun@example.invalid");
        assertThat(signUp.secretHash()).isEqualTo(secretHash("arjun@example.invalid"));
        assertThat(signUp.userAttributes()).extracting(AttributeType::name, AttributeType::value).containsExactlyInAnyOrder(
            Tuple.tuple("email", "arjun@example.invalid"), Tuple.tuple("given_name", "Arjun"),
            Tuple.tuple("family_name", "Rao"), Tuple.tuple("name", "Arjun Rao"));
        assertThat(data(handler.confirm(post("{\"email\":\"arjun@example.invalid\",\"code\":\"123456\",\"returnTo\":\"/\"}")))).isEqualTo(Map.of("step", "SIGN_IN"));
        assertThat(((ConfirmSignUpRequest) calls.get(1)).confirmationCode()).isEqualTo("123456");
        assertThat(data(handler.resend(post("{\"email\":\"arjun@example.invalid\"}")))).isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@e***"));
        // No delivery details: the page still gets a masked address.
        assertThat(data(handler.forgot(post("{\"email\":\"arjun@example.invalid\"}")))).isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@example.invalid"));
        var reset = post("{\"email\":\"arjun@example.invalid\",\"code\":\"654321\",\"newPassword\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}");
        assertThat(data(handler.reset(reset, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/?access=pending"));
        var confirmReset = (ConfirmForgotPasswordRequest) calls.get(4);
        assertThat(confirmReset.confirmationCode()).isEqualTo("654321");
        assertThat(confirmReset.password()).isEqualTo(PASSWORD);
        assertThat(((InitiateAuthRequest) calls.get(5)).authParameters()).containsEntry("PASSWORD", PASSWORD);
    }

    @Test void forgotNeverRevealsWhetherAnAccountExists() {
        answer = m -> { throw UserNotFoundException.builder().message("User does not exist.").build(); };
        var response = handler.forgot(post("{\"email\":\"nobody@example.invalid\"}"));
        assertThat(data(response)).isEqualTo(Map.of("step", "CODE_SENT", "destination", "n***@example.invalid"));
        answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").build(); };
        assertThat(code(handler.signIn(post("{\"email\":\"nobody@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
    }

    @Test void cognitoErrorsMapToThePageVocabularyWithoutProviderText() {
        Map<CognitoIdentityProviderException, List<Object>> cases = new LinkedHashMap<>();
        cases.put(NotAuthorizedException.builder().message("Incorrect username or password.").build(), List.of(401, "INVALID_CREDENTIALS"));
        cases.put(NotAuthorizedException.builder().message("Invalid session for the user, session is expired.").build(), List.of(400, "STEP_EXPIRED"));
        cases.put(UserNotFoundException.builder().build(), List.of(401, "INVALID_CREDENTIALS"));
        cases.put(PasswordResetRequiredException.builder().build(), List.of(401, "INVALID_CREDENTIALS"));
        cases.put(UserNotConfirmedException.builder().build(), List.of(409, "USER_NOT_CONFIRMED"));
        cases.put(CodeMismatchException.builder().build(), List.of(400, "CODE_MISMATCH"));
        cases.put(ExpiredCodeException.builder().build(), List.of(400, "CODE_EXPIRED"));
        cases.put(InvalidPasswordException.builder().build(), List.of(400, "INVALID_PASSWORD"));
        cases.put(UsernameExistsException.builder().build(), List.of(409, "USERNAME_EXISTS"));
        cases.put(TooManyRequestsException.builder().build(), List.of(429, "TOO_MANY_REQUESTS"));
        cases.put(LimitExceededException.builder().build(), List.of(429, "TOO_MANY_REQUESTS"));
        cases.put(TooManyFailedAttemptsException.builder().build(), List.of(429, "TOO_MANY_REQUESTS"));
        cases.put(InvalidParameterException.builder().build(), List.of(400, "INVALID_REQUEST"));
        cases.put(InternalErrorException.builder().message("synthetic provider detail").build(), List.of(503, "SERVICE_UNAVAILABLE"));
        cases.forEach((error, expected) -> {
            var response = PasswordSignInHandler.mapped(new PasswordSignInCognitoClient.Refused(error));
            assertThat(response.getStatusCode().value()).as(error.toString()).isEqualTo(expected.get(0));
            assertThat(response.getBody()).isEqualTo(Map.of("code", expected.get(1)));
        });
        answer = m -> { throw new IllegalStateException("synthetic transport failure"); };
        var response = handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
        assertThat(code(response)).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(response.getBody().toString()).doesNotContain("synthetic transport failure");
    }

    @Test void inputIsBoundedAndValidatedBeforeCognitoIsCalled() {
        answer = m -> InitiateAuthResponse.builder().build();
        for (String body : List.of("not json", "[1,2]", "{}", "{\"email\":\"priya@example.invalid\"}", "{\"email\":\"no-at-sign\",\"password\":\"x\"}",
                "{\"email\":\"priya@example.invalid\",\"password\":\"\"}", "{\"email\":\"priya@example.invalid\",\"password\":7}",
                "{\"email\":\"pri\\u0007ya@example.invalid\",\"password\":\"x\"}", "{\"email\":\"priya@example.invalid\",\"password\":\"" + "x".repeat(257) + "\"}"))
            assertThat(code(handler.signIn(post(body), new MockHttpServletResponse()))).as(body).isEqualTo("INVALID_REQUEST");
        assertThat(code(handler.signUp(post("{\"firstName\":\"\",\"lastName\":\"Rao\",\"email\":\"a@example.invalid\",\"password\":\"x\"}")))).isEqualTo("INVALID_REQUEST");
        assertThat(code(handler.confirm(post("{\"email\":\"a@example.invalid\",\"code\":\"12\"}")))).isEqualTo("INVALID_REQUEST");
        var big = post("{\"email\":\"" + "a".repeat(9000) + "\"}");
        var response = handler.signIn(big, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(413);
        assertThat(calls).isEmpty();
    }

    @Test void repeatedAttemptsAreSlowedPerAccountAndPerAddress() {
        answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").build(); };
        for (int i = 0; i < PasswordSignInThrottle.PER_ACCOUNT; i++)
            assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
        var limited = handler.signIn(post("{\"email\":\"PRIYA@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
        assertThat(limited.getStatusCode().value()).isEqualTo(429);
        assertThat(code(limited)).isEqualTo("TOO_MANY_REQUESTS");
        clock.advance(601);
        assertThat(code(handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
        // One address spraying many accounts.
        var fresh = handler();
        for (int i = 0; i < PasswordSignInThrottle.PER_ADDRESS; i++)
            fresh.signIn(post("{\"email\":\"user" + i + "@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
        assertThat(code(fresh.signIn(post("{\"email\":\"another@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("TOO_MANY_REQUESTS");
    }

    @Test void neitherPasswordsNorCodesReachTheLogs() {
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        var appender = new ListAppender<ILoggingEvent>(); appender.start(); root.addAppender(appender);
        try {
            answer = m -> { throw CodeMismatchException.builder().message("Invalid code").build(); };
            handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            handler.confirm(post("{\"email\":\"priya@example.invalid\",\"code\":\"987654\"}"));
        } finally { root.detachAppender(appender); }
        assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).noneMatch(m -> m.contains(PASSWORD) || m.contains("987654"));
    }

    /** DLV-969 (owner, 2026-11-04): each route's outcome and reason, every limit hit and every Cognito call, never who or what was typed. */
    @Test void outcomesLimitsAndCognitoCallsAreLoggedWithReasonsButNeverTheAccountOrSecrets() {
        var loggers = List.of((Logger) LoggerFactory.getLogger("lookahead.event"), (Logger) LoggerFactory.getLogger("lookahead.limit"),
            (Logger) LoggerFactory.getLogger("lookahead.upstream"));
        var appender = new ListAppender<ILoggingEvent>(); appender.start(); loggers.forEach(logger -> logger.addAppender(appender));
        try {
            answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
            when(completion.completeSignIn(any(), any(), any())).thenReturn("/learn");
            handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Password sign-in succeeded: signed in with Cognito, finishing the sign-in");
            assertThat(appender.list).anyMatch(line -> line.getFormattedMessage().matches("Upstream cognito InitiateAuth succeeded in \\d+ ms"));

            appender.list.clear();
            answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("NotAuthorizedException").build()).build(); };
            for (int i = 0; i < PasswordSignInThrottle.PER_ACCOUNT; i++)
                handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong-" + PASSWORD + "\"}"), new MockHttpServletResponse());
            var wrong = appender.list.stream().filter(line -> line.getLoggerName().equals("lookahead.event")).findFirst().orElseThrow();
            assertThat(wrong.getLevel()).isEqualTo(Level.WARN);
            assertThat(wrong.getFormattedMessage()).isEqualTo("Password sign-in refused: INVALID_CREDENTIALS (wrong email or password)");
            assertThat(OpsLogTest.pairs(wrong)).contains("event.action=sign-in.password", "event.outcome=refused", "reason=INVALID_CREDENTIALS", "http.status=401");
            assertThat(appender.list).anyMatch(line -> OpsLogTest.pairs(line).contains("upstream.code=NotAuthorizedException"));
            // The eleventh attempt for the account: our own limit, named, sized and windowed.
            appender.list.clear();
            handler.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
            var limit = appender.list.stream().filter(line -> line.getLoggerName().equals("lookahead.limit")).findFirst().orElseThrow();
            assertThat(limit.getLevel()).isEqualTo(Level.WARN);
            assertThat(limit.getFormattedMessage()).isEqualTo("Rate limit password-pages.per-account reached: sign-in.password refused, more than 10 password-page attempts for one account in 10 minutes");
            assertThat(OpsLogTest.pairs(limit)).contains("limit.name=password-pages.per-account", "limit.max=10", "limit.window=PT10M", "event.action=sign-in.password");
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Password sign-in refused: TOO_MANY_REQUESTS (too many attempts)");
            // One address spraying accounts trips the per-address limit.
            var sprayed = handler();
            appender.list.clear();
            for (int i = 0; i <= PasswordSignInThrottle.PER_ADDRESS; i++)
                sprayed.forgot(post("{\"email\":\"user" + i + "@example.invalid\"}"));
            assertThat(appender.list).anyMatch(line -> OpsLogTest.pairs(line).contains("limit.name=password-pages.per-address") && OpsLogTest.pairs(line).contains("limit.max=30"));
            // Cognito's own throttling is a limit hit too.
            appender.list.clear();
            answer = m -> { throw TooManyRequestsException.builder().statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("TooManyRequestsException").build()).build(); };
            handler().signUp(post("{\"firstName\":\"Arjun\",\"lastName\":\"Rao\",\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\"}"));
            assertThat(appender.list).anyMatch(line -> line.getLoggerName().equals("lookahead.limit") && OpsLogTest.pairs(line).contains("limit.name=cognito")
                && line.getFormattedMessage().equals("Rate limit cognito reached: sign-up.started refused by Cognito (TooManyRequestsException)"));
            // A failure with no answer: the WARN outcome line names its types; the ERROR upstream line quotes the message with the email masked.
            appender.list.clear();
            answer = m -> { throw new IllegalStateException("synthetic transport failure for arjun@example.invalid"); };
            handler().resend(post("{\"email\":\"arjun@example.invalid\"}"));
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage)
                .contains("Sign-up code resend failed: SERVICE_UNAVAILABLE (Cognito or the sign-in completion was unavailable or answered unexpectedly) after IllegalStateException");
            handler().confirm(post("not json"));
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Sign-up code confirmation refused: INVALID_REQUEST (the form was malformed or a field failed validation)");
        } finally { loggers.forEach(logger -> logger.detachAppender(appender)); }
        assertThat(appender.list).isNotEmpty().allSatisfy(line -> {
            assertThat(line.getFormattedMessage()).doesNotContain("example.invalid", PASSWORD, "synthetic-access", "synthetic-id", "203.0.113.9");
            assertThat(OpsLogTest.pairs(line)).noneMatch(pair -> pair.contains("example.invalid") || pair.contains(PASSWORD) || pair.contains("203.0.113.9"));
        });
    }

    // ----- the error mapping, the outcome line and the route runner (from PasswordSignInAnswerTest) -----

    @Test void cognitoRefusalsWithoutAMessageStillMapAndProviderTextNeverLeaves() {
        var noMessage = PasswordSignInHandler.mapped(new PasswordSignInCognitoClient.Refused(NotAuthorizedException.builder().build()));
        assertThat(noMessage.getStatusCode().value()).isEqualTo(401);
        assertThat(noMessage.getBody()).isEqualTo(Map.of("code", "INVALID_CREDENTIALS"));
        var expired = PasswordSignInHandler.mapped(new PasswordSignInCognitoClient.Refused(UserNotFoundException.builder().message("Invalid session for the user, session is expired.").build()));
        assertThat(expired.getStatusCode().value()).isEqualTo(400);
        assertThat(expired.getBody()).isEqualTo(Map.of("code", "STEP_EXPIRED"));
        var unknown = PasswordSignInHandler.mapped(new PasswordSignInCognitoClient.Refused(InternalErrorException.builder().message("synthetic provider detail").build()));
        assertThat(unknown.getStatusCode().value()).isEqualTo(503);
        assertThat(unknown.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(unknown.getBody().toString()).doesNotContain("synthetic provider detail");
    }

    /** DLV-1015: the outcome line and its three word tables, sentences unchanged since they were in PasswordSignInController. */
    @Test void theOutcomeLineSaysTheRouteAndTheStepInWordsAndHandsTheAnswerBack() {
        try (var log = new LogCapture("lookahead.event")) {
            var sent = PasswordSignInAnswer.step("CODE_SENT", "a***@example.invalid");
            assertThat(PasswordSignInHandler.outcome("sign-up.started", sent, null)).isSameAs(sent);
            assertThat(log.messages()).containsExactly("Sign-up succeeded: code sent");
            assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-up.started", "event.outcome=success", "step=CODE_SENT");
            log.clear();
            Map<String, String> routes = Map.of("sign-in.password", "Password sign-in", "sign-in.challenge", "Sign-in step (new password or code)",
                "sign-up.started", "Sign-up", "sign-up.confirmed", "Sign-up code confirmation", "sign-up.code-resent", "Sign-up code resend",
                "password-reset.requested", "Password reset request", "password-reset.completed", "Password reset");
            Map<String, String> steps = Map.of("SIGNED_IN", "signed in with Cognito, finishing the sign-in", "CODE_SENT", "code sent",
                "SIGN_IN", "the person signs in next", "NEW_PASSWORD", "Cognito requires a new password",
                "APP_CODE", "Cognito requires an authenticator app code", "EMAIL_CODE", "Cognito requires an emailed code");
            routes.forEach((event, route) -> steps.forEach((step, words) -> {
                PasswordSignInHandler.outcome(event, PasswordSignInAnswer.step(step, null), null);
                assertThat(log.last().getFormattedMessage()).isEqualTo(route + " succeeded: " + words);
            }));
            // A route or a step without words is named as it is; an answer without a step reads DONE.
            PasswordSignInHandler.outcome("another.route", PasswordSignInAnswer.step("ANOTHER_STEP", null), null);
            assertThat(log.last().getFormattedMessage()).isEqualTo("another.route succeeded: ANOTHER_STEP");
            PasswordSignInHandler.outcome("sign-up.confirmed", ResponseEntity.ok().build(), null);
            assertThat(log.last().getFormattedMessage()).isEqualTo("Sign-up code confirmation succeeded: DONE");
            assertThat(LogCapture.pairs(log.last())).contains("step=DONE");
        }
    }

    @Test void theOutcomeLineOfARefusalOrFailureCarriesTheCodeItsMeaningAndTheStatus() {
        try (var log = new LogCapture("lookahead.event")) {
            Map<String, String> why = Map.ofEntries(Map.entry("INVALID_CREDENTIALS", "wrong email or password"),
                Map.entry("USER_NOT_CONFIRMED", "the account has not confirmed its email yet"), Map.entry("CODE_MISMATCH", "wrong code"),
                Map.entry("CODE_EXPIRED", "the code expired"), Map.entry("INVALID_PASSWORD", "the password breaks the password rules"),
                Map.entry("USERNAME_EXISTS", "an account with this email already exists"), Map.entry("TOO_MANY_REQUESTS", "too many attempts"),
                Map.entry("STEP_EXPIRED", "the sign-in step expired or was already used"), Map.entry("INVALID_REQUEST", "the form was malformed or a field failed validation"),
                Map.entry("REQUEST_TOO_LARGE", "the request was too large"), Map.entry("SERVICE_UNAVAILABLE", "Cognito or the sign-in completion was unavailable or answered unexpectedly"));
            why.forEach((code, words) -> {
                PasswordSignInHandler.outcome("password-reset.completed", PasswordSignInAnswer.failure(400, code), null);
                assertThat(log.last().getFormattedMessage()).isEqualTo("Password reset refused: " + code + " (" + words + ")");
            });
            log.clear();
            var refused = PasswordSignInAnswer.failure(401, "INVALID_CREDENTIALS");
            assertThat(PasswordSignInHandler.outcome("sign-in.password", refused, null)).isSameAs(refused);
            assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-in.password", "event.outcome=refused", "reason=INVALID_CREDENTIALS", "http.status=401");
            PasswordSignInHandler.outcome("sign-up.code-resent", PasswordSignInAnswer.failure(503, "SERVICE_UNAVAILABLE"), "IllegalStateException < IOException");
            assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
            assertThat(log.last().getFormattedMessage()).isEqualTo("Sign-up code resend failed: SERVICE_UNAVAILABLE "
                + "(Cognito or the sign-in completion was unavailable or answered unexpectedly) after IllegalStateException < IOException");
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-up.code-resent", "event.outcome=failure", "reason=SERVICE_UNAVAILABLE",
                "exception.types=IllegalStateException < IOException", "http.status=503");
            // A code without words, and an answer without a code.
            PasswordSignInHandler.outcome("sign-up.started", PasswordSignInAnswer.failure(418, "ANOTHER_CODE"), null);
            assertThat(log.last().getFormattedMessage()).isEqualTo("Sign-up refused: ANOTHER_CODE (HTTP 418)");
            PasswordSignInHandler.outcome("sign-up.started", ResponseEntity.status(502).build(), null);
            assertThat(log.last().getFormattedMessage()).isEqualTo("Sign-up failed: HTTP_502 (HTTP 502)");
            assertThat(LogCapture.pairs(log.last())).contains("event.outcome=failure", "reason=HTTP_502", "http.status=502");
        }
    }

    static PasswordSignInInput.Body fields() {
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/x");
        request.setContent("{\"email\":\"priya@example.invalid\"}".getBytes(StandardCharsets.UTF_8));
        return PasswordSignInInput.read(request);
    }

    /** DLV-1015: running the route and mapping what it throws. */
    @Test void runAnswersWithTheRoutesOwnAnswerAndNeverRunsARefusedBody() {
        try (var log = new LogCapture("lookahead.event", "lookahead.limit")) {
            var seen = new ArrayList<String>();
            var done = PasswordSignInHandler.run("sign-up.confirmed", body -> { seen.add(body.get("email").asString()); return PasswordSignInAnswer.step("SIGN_IN", null); }, fields());
            assertThat(data(done)).isEqualTo(Map.of("step", "SIGN_IN"));
            assertThat(seen).containsExactly("priya@example.invalid");
            assertThat(log.messages()).containsExactly("Sign-up code confirmation succeeded: the person signs in next");
            log.clear();
            var tooLarge = new PasswordSignInInput.Body(null, PasswordSignInAnswer.failure(413, "REQUEST_TOO_LARGE"));
            var refused = PasswordSignInHandler.run("sign-up.confirmed", body -> { throw new AssertionError("a refused body is never run"); }, tooLarge);
            assertThat(refused).isSameAs(tooLarge.refusal());
            assertThat(log.messages()).containsExactly("Sign-up code confirmation refused: REQUEST_TOO_LARGE (the request was too large)");
            assertThat(LogCapture.pairs(log.last())).contains("reason=REQUEST_TOO_LARGE", "http.status=413");
        }
    }

    @Test void runMapsWhatTheRouteThrowsToThePagesCodes() {
        try (var log = new LogCapture("lookahead.event", "lookahead.limit")) {
            var invalid = PasswordSignInHandler.run("sign-in.password", body -> { throw new IllegalArgumentException("password"); }, fields());
            assertThat(invalid.getStatusCode().value()).isEqualTo(400);
            assertThat(invalid.getBody()).isEqualTo(Map.of("code", "INVALID_REQUEST"));
            assertThat(log.messages()).containsExactly("Password sign-in refused: INVALID_REQUEST (the form was malformed or a field failed validation)");
            log.clear();
            var wrong = PasswordSignInHandler.run("sign-in.password", body -> { throw new PasswordSignInCognitoClient.Refused(NotAuthorizedException.builder().message("Incorrect username or password.").build()); }, fields());
            assertThat(wrong.getStatusCode().value()).isEqualTo(401);
            assertThat(log.messages()).containsExactly("Password sign-in refused: INVALID_CREDENTIALS (wrong email or password)");
            log.clear();
            // Cognito's own throttling: the limit line first, then the outcome line.
            var limited = PasswordSignInHandler.run("sign-up.started", body -> { throw new PasswordSignInCognitoClient.Refused(TooManyRequestsException.builder().statusCode(400)
                .awsErrorDetails(AwsErrorDetails.builder().errorCode("TooManyRequestsException").build()).build()); }, fields());
            assertThat(limited.getStatusCode().value()).isEqualTo(429);
            assertThat(log.messages()).containsExactly("Rate limit cognito reached: sign-up.started refused by Cognito (TooManyRequestsException)",
                "Sign-up refused: TOO_MANY_REQUESTS (too many attempts)");
            assertThat(log.lines().getFirst().getLoggerName()).isEqualTo("lookahead.limit");
            assertThat(log.lines().getFirst().getLevel()).isEqualTo(Level.WARN);
            assertThat(LogCapture.pairs(log.lines().getFirst())).containsExactly("limit.name=cognito", "event.action=sign-up.started", "event.outcome=refused", "reason=TOO_MANY_REQUESTS");
            log.clear();
            var failed = PasswordSignInHandler.run("sign-up.code-resent", body -> { throw new IllegalStateException("synthetic failure for priya@example.invalid"); }, fields());
            assertThat(failed.getStatusCode().value()).isEqualTo(503);
            assertThat(failed.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
            assertThat(log.messages()).containsExactly("Sign-up code resend failed: SERVICE_UNAVAILABLE (Cognito or the sign-in completion was unavailable or answered unexpectedly) after IllegalStateException");
            assertThat(LogCapture.pairs(log.last())).contains("exception.types=IllegalStateException", "http.status=503");
            log.assertNothing("priya", "example.invalid");
        }
    }

    // ----- the step after Cognito's answer (from PasswordSignInSessionTest): a session helper on a fixed clock, no sign-in to finish -----

    final Instant now = Instant.parse("2026-11-02T20:00:00Z");
    final SignInCompletionHandler untouched = mock(SignInCompletionHandler.class);
    final PasswordSignInSession sessions = new PasswordSignInSession(null, null, null, untouched, Clock.fixed(now, ZoneOffset.UTC));
    final PasswordSignInHandler steps = new PasswordSignInHandler(null, null, sessions);

    @Test void aSupportedStepIsKeptForThreeMinutesAndCanBeAnsweredOnce() {
        Map<ChallengeNameType, String> kinds = Map.of(ChallengeNameType.NEW_PASSWORD_REQUIRED, "NEW_PASSWORD",
            ChallengeNameType.SOFTWARE_TOKEN_MFA, "APP_CODE", ChallengeNameType.EMAIL_OTP, "EMAIL_CODE");
        kinds.forEach((challenge, kind) -> {
            var request = new MockHttpServletRequest();
            var answer = steps.next(request, new MockHttpServletResponse(), "priya@example.invalid", "/learn", challenge.toString(), "synthetic-session", null);
            assertThat(answer.getStatusCode().value()).isEqualTo(200);
            assertThat(data(answer)).isEqualTo(Map.of("step", kind));
            var session = request.getSession(false);
            var kept = new PasswordSignInSession.Pending("priya@example.invalid", challenge.toString(), "synthetic-session", now.plusSeconds(180), "/learn");
            assertThat(session.getAttribute("lookaheadPasswordChallenge")).isEqualTo(kept);
            assertThat(sessions.pending(session)).isEqualTo(kept);
            assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isEqualTo(kept);
            sessions.answered(session);
            assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isNull();
            assertThat(sessions.pending(session)).isNull();
        });
        verifyNoInteractions(untouched);
    }

    @Test void anAnswerWithoutTokensOrAUsableStepIsA503ThatNamesTheStepAndKeepsNothing() {
        try (var log = new LogCapture("lookahead.event")) {
            var request = new MockHttpServletRequest();
            var none = steps.next(request, new MockHttpServletResponse(), "priya@example.invalid", "/", null, null, null);
            assertThat(none.getStatusCode().value()).isEqualTo(503);
            assertThat(none.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
            assertThat(log.messages()).containsExactly("Cognito's sign-in answer was incomplete: COGNITO_ANSWER_INCOMPLETE (no tokens and no next step); answered 503");
            assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-in.cognito-step", "event.outcome=failure", "reason=COGNITO_ANSWER_INCOMPLETE", "cognito.challenge=none");
            log.clear();
            for (String session : new String[] {null, "", "  "}) {
                var blank = steps.next(request, new MockHttpServletResponse(), "priya@example.invalid", "/", ChallengeNameType.EMAIL_OTP.toString(), session, null);
                assertThat(blank.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
                assertThat(log.last().getFormattedMessage()).isEqualTo("Cognito's sign-in answer was incomplete: COGNITO_ANSWER_INCOMPLETE (no tokens and no session for step EMAIL_OTP); answered 503");
                assertThat(LogCapture.pairs(log.last())).contains("cognito.challenge=EMAIL_OTP");
            }
            log.clear();
            var unsupported = steps.next(request, new MockHttpServletResponse(), "priya@example.invalid", "/", ChallengeNameType.SMS_MFA.toString(), "synthetic-cognito-session", null);
            assertThat(unsupported.getStatusCode().value()).isEqualTo(503);
            assertThat(unsupported.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
            assertThat(log.messages()).containsExactly("Cognito asked for sign-in step SMS_MFA: COGNITO_STEP_UNSUPPORTED (our sign-in page does not support it; "
                + "check the pool's MFA and sign-in settings); answered 503");
            assertThat(LogCapture.pairs(log.last())).containsExactly("event.action=sign-in.cognito-step", "event.outcome=failure", "reason=COGNITO_STEP_UNSUPPORTED", "cognito.challenge=SMS_MFA");
            assertThat(request.getSession(false)).isNull();
            log.assertNothing("priya", "synthetic-cognito-session");
        }
        verifyNoInteractions(untouched);
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
