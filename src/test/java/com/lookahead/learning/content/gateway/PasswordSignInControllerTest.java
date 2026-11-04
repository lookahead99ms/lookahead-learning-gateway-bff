package com.lookahead.learning.content.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.lookahead.learning.content.oauth.OAuthSettings;
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
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

/** DLV-969: our own email-and-password pages, with Cognito behind each route. */
class PasswordSignInControllerTest {
    static final String PASSWORD = "Synthetic-Passw0rd!x";
    final OAuthSettings settings = OAuthSettings.from(new GatewayDeploymentTest().production());
    final ClientRegistrationRepository registrations = new GatewayClientConfiguration().gatewayClient(settings);
    final HttpSessionOAuth2AuthorizedClientRepository clients = new HttpSessionOAuth2AuthorizedClientRepository();
    final GatewaySecurityHandlers handlers = mock(GatewaySecurityHandlers.class);
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
        if (!(argument instanceof java.util.function.Consumer<?> consumer)) return argument;
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
        @SuppressWarnings("unchecked") var accept = (java.util.function.Consumer<Object>) consumer;
        accept.accept(builder);
        return ((software.amazon.awssdk.utils.builder.SdkBuilder<?, ?>) builder).build();
    }

    final JwtDecoderFactory<ClientRegistration> idDecoders = registration -> token -> Jwt.withTokenValue(token).header("alg", "RS256")
        .issuer(settings.issuer()).subject("synthetic-subject").audience(List.of(settings.clientId()))
        .issuedAt(clock.instant()).expiresAt(clock.instant().plusSeconds(300)).claim("auth_time", clock.instant())
        .claim("token_use", tokenUse).claim("cognito:username", "priya@example.invalid").build();

    PasswordSignInController controller() {
        return new PasswordSignInController(settings, new CognitoPasswordClient(cognito, settings), new PasswordSignInThrottle(clock),
            registrations, idDecoders, clients, handlers, clock);
    }
    PasswordSignInController controller = controller();

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    static MockHttpServletRequest post(String json) {
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/x");
        request.setContent(json.getBytes(StandardCharsets.UTF_8)); request.setContentType("application/json"); request.setRemoteAddr("203.0.113.9");
        return request;
    }
    static Map<?, ?> data(ResponseEntity<?> response) {
        return (Map<?, ?>) ((com.lookahead.learning.content.dto.ApiResponse<?>) response.getBody()).data();
    }
    static String code(ResponseEntity<?> response) { return (String) ((Map<?, ?>) response.getBody()).get("code"); }
    static AuthenticationResultType tokens() {
        return AuthenticationResultType.builder().idToken("synthetic-id").accessToken("synthetic-access").refreshToken("synthetic-refresh").expiresIn(300).tokenType("Bearer").build();
    }
    String secretHash(String username) throws Exception {
        var mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(settings.clientSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return Base64.getEncoder().encodeToString(mac.doFinal((username + settings.clientId()).getBytes(StandardCharsets.UTF_8)));
    }

    @Test void signInBuildsTheOAuthEquivalentSessionAndFinishesThroughTheSharedPath() throws Exception {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        when(handlers.completeSignIn(any(), any(), any())).thenReturn("/learn");
        var request = post("{\"email\":\" Priya@Example.invalid \",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}");
        request.getSession(true); String before = request.getSession().getId();
        var response = controller.signIn(request, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(data(response)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
        var sent = (InitiateAuthRequest) calls.getFirst();
        assertThat(sent.authFlow()).isEqualTo(AuthFlowType.USER_PASSWORD_AUTH);
        assertThat(sent.clientId()).isEqualTo(settings.clientId());
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
        verify(handlers).completeSignIn(org.mockito.ArgumentMatchers.same(request), any(), org.mockito.ArgumentMatchers.eq(authentication));
        // The browser never sees a token.
        assertThat(response.getBody().toString()).doesNotContain("synthetic-access", "synthetic-refresh", "synthetic-id", PASSWORD);
    }

    /** DLV-969 S36: SIGNED_IN carries mergeAvailable only when the shared completion saw Domain's literal true; next stays normal. */
    @Test void signedInCarriesMergeAvailableOnlyWhenDomainSaidTrue() {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        when(handlers.completeSignIn(any(), any(), any())).thenAnswer(call -> {
            ((jakarta.servlet.http.HttpServletRequest) call.getArgument(0)).setAttribute(GatewaySecurityHandlers.MERGE_AVAILABLE, Boolean.TRUE);
            return "/learn";
        });
        var merge = controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(merge)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
        // No attribute (Domain sent false, nothing, or a non-boolean): the field is absent.
        doReturn("/learn").when(handlers).completeSignIn(any(), any(), any());
        var plain = controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(plain)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
        // Only Boolean.TRUE counts as the marker.
        doAnswer(call -> {
            ((jakarta.servlet.http.HttpServletRequest) call.getArgument(0)).setAttribute(GatewaySecurityHandlers.MERGE_AVAILABLE, "true");
            return "/learn";
        }).when(handlers).completeSignIn(any(), any(), any());
        var text = controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(text)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
    }

    /** DLV-969 S36: the flag rides only on a final destination; the challenge and reset routes' final SIGNED_IN carry it too. */
    @Test void mergeAvailableOnlyRidesOnAFinalDestination() {
        String[] next = {"/learn"};
        doAnswer(call -> {
            ((jakarta.servlet.http.HttpServletRequest) call.getArgument(0)).setAttribute(GatewaySecurityHandlers.MERGE_AVAILABLE, Boolean.TRUE);
            return next[0];
        }).when(handlers).completeSignIn(any(), any(), any());
        // A further sign-in step or a refusal page is never a final destination.
        for (String step : new String[] {"/sign-in/choose?returnTo=%2Flearn", "/sign-in?error=admission", "/welcome?access=pending", "/dev/access?error=signin"}) {
            next[0] = step;
            answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens()).build();
            var response = controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(data(response)).as(step).isEqualTo(Map.of("step", "SIGNED_IN", "next", step));
        }
        next[0] = "/learn";
        // The email-code challenge, once answered, is the final sign-in.
        answer = m -> m.equals("initiateAuth")
            ? InitiateAuthResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).session("s").build()
            : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
        var first = post("{\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(data(controller.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "EMAIL_CODE"));
        var code = post("{\"code\":\"123456\"}"); code.setSession(first.getSession());
        assertThat(data(controller.challenge(code, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
        // So is the sign-in that follows a password reset.
        answer = m -> m.equals("confirmForgotPassword") ? ConfirmForgotPasswordResponse.builder().build()
            : InitiateAuthResponse.builder().authenticationResult(tokens()).build();
        var reset = controller.reset(post("{\"email\":\"meera@example.invalid\",\"code\":\"123456\",\"newPassword\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}"), new MockHttpServletResponse());
        assertThat(data(reset)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
    }

    @Test void unsafeReturnFallsBackHomeAndMissingExpiryDefaultsToFiveMinutes() {
        answer = m -> InitiateAuthResponse.builder().authenticationResult(tokens().toBuilder().expiresIn(null).refreshToken(null).build()).build();
        when(handlers.completeSignIn(any(), any(), any())).thenReturn("/");
        var request = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"https://evil.invalid/\"}");
        controller.signIn(request, new MockHttpServletResponse());
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
        var response = controller.signIn(request, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(503);
        assertThat(request.getSession(false) == null || request.getSession().getAttribute("SPRING_SECURITY_CONTEXT") == null).isTrue();
        verifyNoInteractions(handlers);
    }

    @Test void newPasswordChallengeIsAnsweredOnceWithinItsWindow() throws Exception {
        answer = m -> m.equals("initiateAuth")
            ? InitiateAuthResponse.builder().challengeName(ChallengeNameType.NEW_PASSWORD_REQUIRED).session("synthetic-session").build()
            : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
        when(handlers.completeSignIn(any(), any(), any())).thenReturn("/");
        var first = post("{\"email\":\"arjun@example.invalid\",\"password\":\"Temporary-Passw0rd!\"}");
        assertThat(data(controller.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "NEW_PASSWORD"));
        var second = post("{\"newPassword\":\"" + PASSWORD + "\"}"); second.setSession(first.getSession());
        var done = controller.challenge(second, new MockHttpServletResponse());
        assertThat(data(done)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/"));
        var sent = (RespondToAuthChallengeRequest) calls.get(1);
        assertThat(sent.challengeName()).isEqualTo(ChallengeNameType.NEW_PASSWORD_REQUIRED);
        assertThat(sent.session()).isEqualTo("synthetic-session");
        assertThat(sent.challengeResponses()).containsEntry("NEW_PASSWORD", PASSWORD).containsEntry("USERNAME", "arjun@example.invalid")
            .containsEntry("SECRET_HASH", secretHash("arjun@example.invalid"));
        // The challenge cannot be replayed.
        var replay = post("{\"newPassword\":\"" + PASSWORD + "\"}"); replay.setSession(second.getSession());
        assertThat(code(controller.challenge(replay, new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
    }

    @Test void challengeWithoutPendingStateOrAfterThreeMinutesIsExpired() {
        assertThat(code(controller.challenge(post("{\"code\":\"123456\"}"), new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
        answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SOFTWARE_TOKEN_MFA).session("s").build();
        var first = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
        assertThat(data(controller.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "APP_CODE"));
        clock.advance(181);
        var late = post("{\"code\":\"123456\"}"); late.setSession(first.getSession());
        assertThat(code(controller.challenge(late, new MockHttpServletResponse()))).isEqualTo("STEP_EXPIRED");
        assertThat(first.getSession().getAttribute(PasswordSignInController.PENDING)).isNull();
    }

    @Test void codeChallengesMapToAppAndEmailAndUnsupportedOnesFailClosed() {
        when(handlers.completeSignIn(any(), any(), any())).thenReturn("/");
        for (var pair : List.of(List.of(ChallengeNameType.SOFTWARE_TOKEN_MFA, "APP_CODE", "SOFTWARE_TOKEN_MFA_CODE"), List.of(ChallengeNameType.EMAIL_OTP, "EMAIL_CODE", "EMAIL_OTP_CODE"))) {
            calls.clear();
            answer = m -> m.equals("initiateAuth")
                ? InitiateAuthResponse.builder().challengeName((ChallengeNameType) pair.get(0)).session("s").build()
                : RespondToAuthChallengeResponse.builder().authenticationResult(tokens()).build();
            var first = post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}");
            assertThat(data(controller.signIn(first, new MockHttpServletResponse()))).isEqualTo(Map.of("step", pair.get(1)));
            var bad = post("{\"code\":\"12ab56\"}"); bad.setSession(first.getSession());
            assertThat(code(controller.challenge(bad, new MockHttpServletResponse()))).isEqualTo("INVALID_REQUEST");
            var good = post("{\"code\":\"123456\"}"); good.setSession(first.getSession());
            assertThat(data(controller.challenge(good, new MockHttpServletResponse())).get("step")).isEqualTo("SIGNED_IN");
            assertThat(((RespondToAuthChallengeRequest) calls.get(1)).challengeResponses()).containsEntry((String) pair.get(2), "123456");
        }
        answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SMS_MFA).session("s").build();
        assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
        answer = m -> InitiateAuthResponse.builder().build();
        assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
    }

    /** DLV-969: an unsupported or incomplete Cognito step names the step; the page still only sees SERVICE_UNAVAILABLE. */
    @Test void anUnsupportedCognitoStepIsNamedInTheLog() {
        try (var log = new com.lookahead.gateway.LogCapture("lookahead.event")) {
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.SMS_MFA).session("synthetic-cognito-session").build();
            assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
            var step = log.lines().stream().filter(line -> "sign-in.cognito-step".equals(line.getKeyValuePairs().getFirst().value)).toList();
            assertThat(step).hasSize(1);
            assertThat(step.getFirst().getFormattedMessage()).startsWith("Cognito asked for sign-in step SMS_MFA, which our sign-in page does not support");
            assertThat(com.lookahead.gateway.LogCapture.pairs(step.getFirst())).contains("reason=COGNITO_STEP_UNSUPPORTED", "cognito.challenge=SMS_MFA");
            log.clear();
            answer = m -> InitiateAuthResponse.builder().challengeName(ChallengeNameType.EMAIL_OTP).build();
            assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("SERVICE_UNAVAILABLE");
            assertThat(log.messages()).contains("Cognito's sign-in answer had no tokens and no session for step EMAIL_OTP; answered 503");
            log.clear();
            answer = m -> InitiateAuthResponse.builder().build();
            controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(log.messages()).contains("Cognito's sign-in answer had no tokens and no next step; answered 503");
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
        when(handlers.completeSignIn(any(), any(), any())).thenReturn("/?access=pending");
        assertThat(data(controller.signUp(post("{\"firstName\":\" Arjun \",\"lastName\":\"Rao\",\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\",\"returnTo\":\"/\"}"))))
            .isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@e***"));
        var signUp = (SignUpRequest) calls.getFirst();
        assertThat(signUp.username()).isEqualTo("arjun@example.invalid");
        assertThat(signUp.secretHash()).isEqualTo(secretHash("arjun@example.invalid"));
        assertThat(signUp.userAttributes()).extracting(AttributeType::name, AttributeType::value).containsExactlyInAnyOrder(
            org.assertj.core.groups.Tuple.tuple("email", "arjun@example.invalid"), org.assertj.core.groups.Tuple.tuple("given_name", "Arjun"),
            org.assertj.core.groups.Tuple.tuple("family_name", "Rao"), org.assertj.core.groups.Tuple.tuple("name", "Arjun Rao"));
        assertThat(data(controller.confirm(post("{\"email\":\"arjun@example.invalid\",\"code\":\"123456\",\"returnTo\":\"/\"}")))).isEqualTo(Map.of("step", "SIGN_IN"));
        assertThat(((ConfirmSignUpRequest) calls.get(1)).confirmationCode()).isEqualTo("123456");
        assertThat(data(controller.resend(post("{\"email\":\"arjun@example.invalid\"}")))).isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@e***"));
        // No delivery details: the page still gets a masked address.
        assertThat(data(controller.forgot(post("{\"email\":\"arjun@example.invalid\"}")))).isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@example.invalid"));
        var reset = post("{\"email\":\"arjun@example.invalid\",\"code\":\"654321\",\"newPassword\":\"" + PASSWORD + "\",\"returnTo\":\"/learn\"}");
        assertThat(data(controller.reset(reset, new MockHttpServletResponse()))).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/?access=pending"));
        var confirmReset = (ConfirmForgotPasswordRequest) calls.get(4);
        assertThat(confirmReset.confirmationCode()).isEqualTo("654321");
        assertThat(confirmReset.password()).isEqualTo(PASSWORD);
        assertThat(((InitiateAuthRequest) calls.get(5)).authParameters()).containsEntry("PASSWORD", PASSWORD);
    }

    @Test void forgotNeverRevealsWhetherAnAccountExists() {
        answer = m -> { throw UserNotFoundException.builder().message("User does not exist.").build(); };
        var response = controller.forgot(post("{\"email\":\"nobody@example.invalid\"}"));
        assertThat(data(response)).isEqualTo(Map.of("step", "CODE_SENT", "destination", "n***@example.invalid"));
        answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").build(); };
        assertThat(code(controller.signIn(post("{\"email\":\"nobody@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
    }

    @Test void cognitoErrorsMapToThePageVocabularyWithoutProviderText() {
        Map<CognitoIdentityProviderException, List<Object>> cases = new java.util.LinkedHashMap<>();
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
            var response = PasswordSignInController.mapped(error);
            assertThat(response.getStatusCode().value()).as(error.toString()).isEqualTo(expected.get(0));
            assertThat(response.getBody()).isEqualTo(Map.of("code", expected.get(1)));
        });
        answer = m -> { throw new IllegalStateException("synthetic transport failure"); };
        var response = controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
        assertThat(code(response)).isEqualTo("SERVICE_UNAVAILABLE");
        assertThat(response.getBody().toString()).doesNotContain("synthetic transport failure");
    }

    @Test void inputIsBoundedAndValidatedBeforeCognitoIsCalled() {
        answer = m -> InitiateAuthResponse.builder().build();
        for (String body : List.of("not json", "[1,2]", "{}", "{\"email\":\"priya@example.invalid\"}", "{\"email\":\"no-at-sign\",\"password\":\"x\"}",
                "{\"email\":\"priya@example.invalid\",\"password\":\"\"}", "{\"email\":\"priya@example.invalid\",\"password\":7}",
                "{\"email\":\"pri\\u0007ya@example.invalid\",\"password\":\"x\"}", "{\"email\":\"priya@example.invalid\",\"password\":\"" + "x".repeat(257) + "\"}"))
            assertThat(code(controller.signIn(post(body), new MockHttpServletResponse()))).as(body).isEqualTo("INVALID_REQUEST");
        assertThat(code(controller.signUp(post("{\"firstName\":\"\",\"lastName\":\"Rao\",\"email\":\"a@example.invalid\",\"password\":\"x\"}")))).isEqualTo("INVALID_REQUEST");
        assertThat(code(controller.confirm(post("{\"email\":\"a@example.invalid\",\"code\":\"12\"}")))).isEqualTo("INVALID_REQUEST");
        var big = post("{\"email\":\"" + "a".repeat(9000) + "\"}");
        var response = controller.signIn(big, new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(413);
        assertThat(calls).isEmpty();
    }

    @Test void repeatedAttemptsAreSlowedPerAccountAndPerAddress() {
        answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").build(); };
        for (int i = 0; i < PasswordSignInThrottle.PER_ACCOUNT; i++)
            assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
        var limited = controller.signIn(post("{\"email\":\"PRIYA@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
        assertThat(limited.getStatusCode().value()).isEqualTo(429);
        assertThat(code(limited)).isEqualTo("TOO_MANY_REQUESTS");
        clock.advance(601);
        assertThat(code(controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("INVALID_CREDENTIALS");
        // One address spraying many accounts.
        var fresh = controller();
        for (int i = 0; i < PasswordSignInThrottle.PER_ADDRESS; i++)
            fresh.signIn(post("{\"email\":\"user" + i + "@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
        assertThat(code(fresh.signIn(post("{\"email\":\"another@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse()))).isEqualTo("TOO_MANY_REQUESTS");
    }

    @Test void throttleForgetsOldKeysWhenItGrowsLarge() {
        var throttle = new PasswordSignInThrottle(clock);
        for (int i = 0; i <= PasswordSignInThrottle.MAX_KEYS; i++) throttle.allow("198.51.100." + (i % 250), "user" + i + "@example.invalid");
        clock.advance(601);
        assertThat(throttle.allow("198.51.100.1", "user1@example.invalid")).isTrue();
        assertThat(throttle.allow(null, null)).isTrue();
    }

    @Test void neitherPasswordsNorCodesReachTheLogs() {
        Logger root = (Logger) LoggerFactory.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
        var appender = new ListAppender<ILoggingEvent>(); appender.start(); root.addAppender(appender);
        try {
            answer = m -> { throw CodeMismatchException.builder().message("Invalid code").build(); };
            controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            controller.confirm(post("{\"email\":\"priya@example.invalid\",\"code\":\"987654\"}"));
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
            when(handlers.completeSignIn(any(), any(), any())).thenReturn("/learn");
            controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"" + PASSWORD + "\"}"), new MockHttpServletResponse());
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Password sign-in succeeded: signed in with Cognito, finishing the sign-in");
            assertThat(appender.list).anyMatch(line -> line.getFormattedMessage().matches("Upstream cognito InitiateAuth succeeded in \\d+ ms"));

            appender.list.clear();
            answer = m -> { throw NotAuthorizedException.builder().message("Incorrect username or password.").statusCode(400)
                .awsErrorDetails(software.amazon.awssdk.awscore.exception.AwsErrorDetails.builder().errorCode("NotAuthorizedException").build()).build(); };
            for (int i = 0; i < PasswordSignInThrottle.PER_ACCOUNT; i++)
                controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong-" + PASSWORD + "\"}"), new MockHttpServletResponse());
            var wrong = appender.list.stream().filter(line -> line.getLoggerName().equals("lookahead.event")).findFirst().orElseThrow();
            assertThat(wrong.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(wrong.getFormattedMessage()).isEqualTo("Password sign-in refused: INVALID_CREDENTIALS (wrong email or password)");
            assertThat(OpsLogTest.pairs(wrong)).contains("event.action=sign-in.password", "event.outcome=refused", "reason=INVALID_CREDENTIALS", "http.status=401");
            assertThat(appender.list).anyMatch(line -> OpsLogTest.pairs(line).contains("upstream.code=NotAuthorizedException"));
            // The eleventh attempt for the account: our own limit, named, sized and windowed.
            appender.list.clear();
            controller.signIn(post("{\"email\":\"priya@example.invalid\",\"password\":\"wrong\"}"), new MockHttpServletResponse());
            var limit = appender.list.stream().filter(line -> line.getLoggerName().equals("lookahead.limit")).findFirst().orElseThrow();
            assertThat(limit.getLevel()).isEqualTo(ch.qos.logback.classic.Level.WARN);
            assertThat(limit.getFormattedMessage()).isEqualTo("Rate limit reached: sign-in.password refused, more than 10 password-page attempts for one account in 10 minutes");
            assertThat(OpsLogTest.pairs(limit)).contains("limit.name=password-pages.per-account", "limit.max=10", "limit.window=PT10M", "event.action=sign-in.password");
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Password sign-in refused: TOO_MANY_REQUESTS (too many attempts)");
            // One address spraying accounts trips the per-address limit.
            var sprayed = controller();
            appender.list.clear();
            for (int i = 0; i <= PasswordSignInThrottle.PER_ADDRESS; i++)
                sprayed.forgot(post("{\"email\":\"user" + i + "@example.invalid\"}"));
            assertThat(appender.list).anyMatch(line -> OpsLogTest.pairs(line).contains("limit.name=password-pages.per-address") && OpsLogTest.pairs(line).contains("limit.max=30"));
            // Cognito's own throttling is a limit hit too.
            appender.list.clear();
            answer = m -> { throw TooManyRequestsException.builder().statusCode(400)
                .awsErrorDetails(software.amazon.awssdk.awscore.exception.AwsErrorDetails.builder().errorCode("TooManyRequestsException").build()).build(); };
            controller().signUp(post("{\"firstName\":\"Arjun\",\"lastName\":\"Rao\",\"email\":\"arjun@example.invalid\",\"password\":\"" + PASSWORD + "\"}"));
            assertThat(appender.list).anyMatch(line -> line.getLoggerName().equals("lookahead.limit") && OpsLogTest.pairs(line).contains("limit.name=cognito")
                && line.getFormattedMessage().equals("Rate limit reached: sign-up.started refused by Cognito (TooManyRequestsException)"));
            // A failure with no answer names its types, not its message.
            appender.list.clear();
            answer = m -> { throw new IllegalStateException("synthetic transport failure for arjun@example.invalid"); };
            controller().resend(post("{\"email\":\"arjun@example.invalid\"}"));
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage)
                .contains("Sign-up code resend failed: SERVICE_UNAVAILABLE (Cognito or the sign-in completion was unavailable or answered unexpectedly) after IllegalStateException");
            controller().confirm(post("not json"));
            assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).contains("Sign-up code confirmation refused: INVALID_REQUEST (the form was malformed or a field failed validation)");
        } finally { loggers.forEach(logger -> logger.detachAppender(appender)); }
        assertThat(appender.list).isNotEmpty().allSatisfy(line -> {
            assertThat(line.getFormattedMessage()).doesNotContain("example.invalid", PASSWORD, "synthetic-access", "synthetic-id", "203.0.113.9");
            assertThat(OpsLogTest.pairs(line)).noneMatch(pair -> pair.contains("example.invalid") || pair.contains(PASSWORD) || pair.contains("203.0.113.9"));
        });
    }

    @Test void clientAddressUsesTheLastForwardedHop() {
        var request = new MockHttpServletRequest(); request.setRemoteAddr("10.0.0.5");
        assertThat(PasswordSignInController.address(request)).isEqualTo("10.0.0.5");
        request.addHeader("X-Forwarded-For", "198.51.100.7, 203.0.113.9");
        assertThat(PasswordSignInController.address(request)).isEqualTo("203.0.113.9");
        var odd = new MockHttpServletRequest(); odd.setRemoteAddr("10.0.0.6"); odd.addHeader("X-Forwarded-For", "x".repeat(80));
        assertThat(PasswordSignInController.address(odd)).isEqualTo("10.0.0.6");
        assertThat(PasswordSignInController.masked("not-an-email")).isEqualTo("your email");
    }

    @Test void productionConstructorBuildsAnAnonymousRegionalClient() {
        var built = PasswordSignInController.cognitoClient(settings);
        assertThat(built.serviceClientConfiguration().region().id()).isEqualTo(java.net.URI.create(settings.issuer()).getHost().split("\\.")[1]);
        built.close();
        assertThat(new PasswordSignInController(settings, registrations, idDecoders, clients, handlers)).isNotNull();
    }

    @Test void anEarlierPendingSignInChallengeDoesNotBlockANewPasswordSignIn() {
        var filter = new LogicalSignInFilter(null, null, settings);
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/sign-in");
        request.getSession().setAttribute(CloudGatewaySessions.CHALLENGE, "c".repeat(43));
        assertThat(filter.shouldNotFilter(request)).isTrue();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", "/bff/api/v1/plans"))).isFalse();
    }

    static final class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant now) { this.now = now; }
        void advance(long seconds) { now = now.plusSeconds(seconds); }
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
