package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.client.PasswordSignInCognitoClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.session.PasswordSignInSession;
import com.lookahead.gateway.util.AccountMergeOffer;
import com.lookahead.gateway.util.PasswordSignInAnswer;
import com.lookahead.gateway.util.SignInReturnDestination;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;

/**
 * DLV-969: what the seven routes of our own sign-in and sign-up pages do, one public method per
 * route. Each reads and checks the fields it was sent, counts the attempt, calls one Cognito
 * user-pool operation through {@code PasswordSignInCognitoClient} and answers with the next step
 * for the page; tokens never leave the Gateway BFF. A successful sign-in builds the same
 * server-side session as the OAuth callback and finishes through {@code
 * SignInCompletionHandler.completeSignIn}, so the DEV gate, Domain admission, waiting accounts and
 * sign-in challenges behave identically. Every answer is recorded by one {@code lookahead.event}
 * line: the outcome and the stable reason, never the input.
 */
public final class PasswordSignInHandler {
  private final PasswordSignInCognitoClient cognito;
  private final PasswordSignInThrottle throttle;
  private final PasswordSignInSession sessions;

  public PasswordSignInHandler(
      PasswordSignInCognitoClient cognito,
      PasswordSignInThrottle throttle,
      PasswordSignInSession sessions) {
    this.cognito = cognito;
    this.throttle = throttle;
    this.sessions = sessions;
  }

  public ResponseEntity<?> signIn(HttpServletRequest request, HttpServletResponse response) {
    return handle(
        request,
        "sign-in.password",
        body -> {
          String email = PasswordSignInInput.email(body),
              password = PasswordSignInInput.secret(body, "password"),
              returnTo =
                  SignInReturnDestination.safeReturn(
                      PasswordSignInInput.text(body, "returnTo", 2048, true));
          if (!throttle.allow("sign-in.password", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          var result = cognito.signIn(email, password);
          return next(
              request,
              response,
              email,
              returnTo,
              result.stepName(),
              result.session(),
              result.tokens());
        });
  }

  public ResponseEntity<?> challenge(HttpServletRequest request, HttpServletResponse response) {
    return handle(
        request,
        "sign-in.challenge",
        body -> {
          var session = request.getSession(false);
          var pending = sessions.pending(session);
          if (pending == null) return PasswordSignInAnswer.failure(400, "STEP_EXPIRED");
          if (!throttle.allow(
              "sign-in.challenge", PasswordSignInInput.address(request), pending.username()))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          var result =
              cognito.respond(
                  pending.challenge(),
                  pending.session(),
                  pending.username(),
                  () -> PasswordSignInInput.secret(body, "newPassword"),
                  () -> PasswordSignInInput.code(body));
          sessions.answered(session);
          return next(
              request,
              response,
              pending.username(),
              pending.returnTo(),
              result.stepName(),
              result.session(),
              result.tokens());
        });
  }

  public ResponseEntity<?> signUp(HttpServletRequest request) {
    return handle(
        request,
        "sign-up.started",
        body -> {
          String email = PasswordSignInInput.email(body),
              password = PasswordSignInInput.secret(body, "password"),
              first = PasswordSignInInput.name(body, "firstName"),
              last = PasswordSignInInput.name(body, "lastName");
          if (!throttle.allow("sign-up.started", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          var result = cognito.signUp(email, password, first, last);
          return PasswordSignInAnswer.step(
              "CODE_SENT", PasswordSignInAnswer.destination(result, email));
        });
  }

  public ResponseEntity<?> confirm(HttpServletRequest request) {
    return handle(
        request,
        "sign-up.confirmed",
        body -> {
          String email = PasswordSignInInput.email(body), code = PasswordSignInInput.code(body);
          if (!throttle.allow("sign-up.confirmed", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          cognito.confirmSignUp(email, code);
          // The password is never kept between requests, so the person signs in once more after
          // confirming.
          return PasswordSignInAnswer.step("SIGN_IN", null);
        });
  }

  public ResponseEntity<?> resend(HttpServletRequest request) {
    return handle(
        request,
        "sign-up.code-resent",
        body -> {
          String email = PasswordSignInInput.email(body);
          if (!throttle.allow("sign-up.code-resent", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          var result = cognito.resend(email);
          return PasswordSignInAnswer.step(
              "CODE_SENT", PasswordSignInAnswer.destination(result, email));
        });
  }

  public ResponseEntity<?> forgot(HttpServletRequest request) {
    return handle(
        request,
        "password-reset.requested",
        body -> {
          String email = PasswordSignInInput.email(body);
          if (!throttle.allow(
              "password-reset.requested", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          try {
            var result = cognito.forgot(email);
            return PasswordSignInAnswer.step(
                "CODE_SENT", PasswordSignInAnswer.destination(result, email));
          } catch (PasswordSignInCognitoClient.Refused unknown) {
            if (!unknown.is("UserNotFoundException") && !unknown.is("InvalidParameterException"))
              throw unknown;
            // The same answer whether or not the account exists, so the page cannot be used to
            // probe for accounts.
            return PasswordSignInAnswer.step("CODE_SENT", PasswordSignInAnswer.masked(email));
          }
        });
  }

  public ResponseEntity<?> reset(HttpServletRequest request, HttpServletResponse response) {
    return handle(
        request,
        "password-reset.completed",
        body -> {
          String email = PasswordSignInInput.email(body),
              code = PasswordSignInInput.code(body),
              password = PasswordSignInInput.secret(body, "newPassword"),
              returnTo =
                  SignInReturnDestination.safeReturn(
                      PasswordSignInInput.text(body, "returnTo", 2048, true));
          if (!throttle.allow(
              "password-reset.completed", PasswordSignInInput.address(request), email))
            return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
          cognito.reset(email, code, password);
          // The new password is in this request; signing in with it now saves a second form, and
          // nothing is stored.
          var result = cognito.signIn(email, password);
          return next(
              request,
              response,
              email,
              returnTo,
              result.stepName(),
              result.session(),
              result.tokens());
        });
  }

  /** Reads the body, runs the route on it and answers. */
  private ResponseEntity<?> handle(HttpServletRequest request, String event, Action action) {
    return run(event, action, PasswordSignInInput.read(request));
  }

  /**
   * What Cognito's answer means for the page: signed in, a further step kept as pending, or an
   * answer we cannot use.
   */
  ResponseEntity<?> next(
      HttpServletRequest request,
      HttpServletResponse response,
      String username,
      String returnTo,
      String stepName,
      String session,
      PasswordSignInCognitoClient.Tokens tokens) {
    if (tokens != null) {
      String next = sessions.finish(request, response, returnTo, tokens);
      // DLV-969 S36: the page shows "Check your inbox" itself, so the next path stays the normal
      // one. Only a final destination carries it; a further sign-in step (/sign-in/choose, an error
      // or waiting page) never does.
      boolean merge =
          AccountMergeOffer.mergeAvailable(request)
              && SignInReturnDestination.safeReturn(next).equals(next);
      return PasswordSignInAnswer.step("SIGNED_IN", null, next, merge);
    }
    if (stepName == null || session == null || session.isBlank()) {
      // DLV-969: Cognito answered with neither tokens nor a usable next step; the page only sees
      // SERVICE_UNAVAILABLE.
      OpsLog.failed("sign-in.cognito-step", "COGNITO_ANSWER_INCOMPLETE")
          .addKeyValue("cognito.challenge", stepName == null ? "none" : stepName)
          .log(
              "Cognito's sign-in answer was incomplete: COGNITO_ANSWER_INCOMPLETE (no tokens and"
                  + " {}); answered 503",
              stepName == null ? "no next step" : "no session for step " + stepName);
      return PasswordSignInAnswer.failure(503, "SERVICE_UNAVAILABLE");
    }
    String kind =
        switch (stepName) {
          case "NEW_PASSWORD_REQUIRED" -> "NEW_PASSWORD";
          case "SOFTWARE_TOKEN_MFA" -> "APP_CODE";
          case "EMAIL_OTP" -> "EMAIL_CODE";
          default -> null;
        };
    if (kind == null) {
      OpsLog.failed("sign-in.cognito-step", "COGNITO_STEP_UNSUPPORTED")
          .addKeyValue("cognito.challenge", stepName)
          .log(
              "Cognito asked for sign-in step {}: COGNITO_STEP_UNSUPPORTED (our sign-in page does"
                  + " not support it; check the pool's MFA and sign-in settings); answered 503",
              stepName);
      return PasswordSignInAnswer.failure(503, "SERVICE_UNAVAILABLE");
    }
    sessions.keep(request, username, stepName, session, returnTo);
    return PasswordSignInAnswer.step(kind, null);
  }

  /**
   * Cognito's answers in the page's vocabulary; never the provider's own message, which may name
   * the account.
   */
  static ResponseEntity<?> mapped(PasswordSignInCognitoClient.Refused rejected) {
    if (rejected.is("NotAuthorizedException")
        || rejected.is("UserNotFoundException")
        || rejected.is("PasswordResetRequiredException"))
      return rejected.getMessage() != null && rejected.getMessage().contains("session is expired")
          ? PasswordSignInAnswer.failure(400, "STEP_EXPIRED")
          : PasswordSignInAnswer.failure(401, "INVALID_CREDENTIALS");
    if (rejected.is("UserNotConfirmedException"))
      return PasswordSignInAnswer.failure(409, "USER_NOT_CONFIRMED");
    if (rejected.is("CodeMismatchException"))
      return PasswordSignInAnswer.failure(400, "CODE_MISMATCH");
    if (rejected.is("ExpiredCodeException"))
      return PasswordSignInAnswer.failure(400, "CODE_EXPIRED");
    if (rejected.is("InvalidPasswordException"))
      return PasswordSignInAnswer.failure(400, "INVALID_PASSWORD");
    if (rejected.is("UsernameExistsException"))
      return PasswordSignInAnswer.failure(409, "USERNAME_EXISTS");
    if (rejected.is("TooManyRequestsException")
        || rejected.is("LimitExceededException")
        || rejected.is("TooManyFailedAttemptsException"))
      return PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
    if (rejected.is("InvalidParameterException"))
      return PasswordSignInAnswer.failure(400, "INVALID_REQUEST");
    return PasswordSignInAnswer.failure(503, "SERVICE_UNAVAILABLE");
  }

  /** One route's work on the fields it was sent. */
  interface Action {
    ResponseEntity<?> apply(JsonNode body);
  }

  /**
   * Runs one page route and writes its {@code lookahead.event} line: the outcome and the stable
   * reason, never the input.
   */
  static ResponseEntity<?> run(String event, Action action, PasswordSignInInput.Body input) {
    if (input.refusal() != null) return outcome(event, input.refusal(), null);
    JsonNode body = input.fields();
    try {
      return outcome(event, action.apply(body), null);
    } catch (IllegalArgumentException invalid) {
      return outcome(event, PasswordSignInAnswer.failure(400, "INVALID_REQUEST"), null);
    } catch (PasswordSignInCognitoClient.Refused rejected) {
      var answer = mapped(rejected);
      if (answer.getStatusCode().value() == 429)
        OpsLog.limit(
            "cognito",
            0,
            null,
            event,
            "Rate limit cognito reached: {} refused by Cognito ({})",
            event,
            rejected.code());
      return outcome(event, answer, null);
    } catch (RuntimeException unavailable) {
      return outcome(
          event,
          PasswordSignInAnswer.failure(503, "SERVICE_UNAVAILABLE"),
          OpsLog.types(unavailable));
    }
  }

  /** What each route is, in words, for the log line. */
  private static final Map<String, String> ROUTES =
      Map.of(
          "sign-in.password",
          "Password sign-in",
          "sign-in.challenge",
          "Sign-in step (new password or code)",
          "sign-up.started",
          "Sign-up",
          "sign-up.confirmed",
          "Sign-up code confirmation",
          "sign-up.code-resent",
          "Sign-up code resend",
          "password-reset.requested",
          "Password reset request",
          "password-reset.completed",
          "Password reset");

  /** The next step the page is sent to, in words. */
  private static final Map<String, String> STEPS =
      Map.of(
          "SIGNED_IN",
          "signed in with Cognito, finishing the sign-in",
          "CODE_SENT",
          "code sent",
          "SIGN_IN",
          "the person signs in next",
          "NEW_PASSWORD",
          "Cognito requires a new password",
          "APP_CODE",
          "Cognito requires an authenticator app code",
          "EMAIL_CODE",
          "Cognito requires an emailed code");

  /** Each refusal code, in words. */
  private static final Map<String, String> WHY =
      Map.ofEntries(
          Map.entry("INVALID_CREDENTIALS", "wrong email or password"),
          Map.entry("USER_NOT_CONFIRMED", "the account has not confirmed its email yet"),
          Map.entry("CODE_MISMATCH", "wrong code"),
          Map.entry("CODE_EXPIRED", "the code expired"),
          Map.entry("INVALID_PASSWORD", "the password breaks the password rules"),
          Map.entry("USERNAME_EXISTS", "an account with this email already exists"),
          Map.entry("TOO_MANY_REQUESTS", "too many attempts"),
          Map.entry("STEP_EXPIRED", "the sign-in step expired or was already used"),
          Map.entry("INVALID_REQUEST", "the form was malformed or a field failed validation"),
          Map.entry("REQUEST_TOO_LARGE", "the request was too large"),
          Map.entry(
              "SERVICE_UNAVAILABLE",
              "Cognito or the sign-in completion was unavailable or answered unexpectedly"));

  static ResponseEntity<?> outcome(String event, ResponseEntity<?> answer, String types) {
    int status = answer.getStatusCode().value();
    String what = ROUTES.getOrDefault(event, event);
    if (status < 400) {
      String step =
          answer.getBody() instanceof ApiResponse<?> api
                  && api.data() instanceof Map<?, ?> data
                  && data.get("step") instanceof String value
              ? value
              : "DONE";
      OpsLog.success(event)
          .addKeyValue("step", step)
          .log("{} succeeded: {}", what, STEPS.getOrDefault(step, step));
      return answer;
    }
    String reason =
        answer.getBody() instanceof Map<?, ?> body && body.get("code") instanceof String code
            ? code
            : "HTTP_" + status;
    var line = status >= 500 ? OpsLog.failed(event, reason) : OpsLog.refused(event, reason);
    if (types != null) line = line.addKeyValue("exception.types", types);
    line.addKeyValue("http.status", status)
        .log(
            "{} {}: {} ({}){}",
            what,
            status >= 500 ? "failed" : "refused",
            reason,
            WHY.getOrDefault(reason, "HTTP " + status),
            types == null ? "" : " after " + types);
    return answer;
  }
}
