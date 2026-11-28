package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.lookahead.gateway.security.handler.SignInCompletionHandler;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

/**
 * DLV-1015: the pending sign-in step. What Cognito's answer means for the page and the signed-in
 * session built from tokens are driven through PasswordSignInHandler in PasswordSignInHandlerTest.
 */
class PasswordSignInSessionTest {
  final Instant now = Instant.parse("2026-11-02T20:00:00Z");
  final SignInCompletionHandler completion = mock(SignInCompletionHandler.class);
  final PasswordSignInSession sessions =
      new PasswordSignInSession(null, null, null, completion, Clock.fixed(now, ZoneOffset.UTC));

  /**
   * DLV-1015: which steps the page answers is decided in PasswordSignInHandler; the session keeps
   * whatever name it is handed.
   */
  @Test
  void aStepIsKeptForThreeMinutesUnderCognitosNameAndCanBeAnsweredOnce() {
    for (String challenge :
        new String[] {"NEW_PASSWORD_REQUIRED", "SOFTWARE_TOKEN_MFA", "EMAIL_OTP"}) {
      var request = new MockHttpServletRequest();
      sessions.keep(request, "priya@example.invalid", challenge, "synthetic-session", "/learn");
      var session = request.getSession(false);
      var kept =
          new PasswordSignInSession.Pending(
              "priya@example.invalid",
              challenge,
              "synthetic-session",
              now.plusSeconds(180),
              "/learn");
      assertThat(session.getAttribute("lookaheadPasswordChallenge")).isEqualTo(kept);
      assertThat(sessions.pending(session)).isEqualTo(kept);
      assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isEqualTo(kept);
      sessions.answered(session);
      assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isNull();
      assertThat(sessions.pending(session)).isNull();
      // A later step in the same browser session replaces the one before it.
      sessions.keep(request, "priya@example.invalid", "EMAIL_OTP", "first", "/learn");
      sessions.keep(request, "priya@example.invalid", challenge, "second", "/grow");
      assertThat(request.getSession(false)).isSameAs(session);
      assertThat(sessions.pending(session))
          .isEqualTo(
              new PasswordSignInSession.Pending(
                  "priya@example.invalid", challenge, "second", now.plusSeconds(180), "/grow"));
    }
    verifyNoInteractions(completion);
  }

  @Test
  void aPendingStepIsGoneWhenItsWindowHasPassedOrNothingUsableIsKept() {
    assertThat(sessions.pending(null)).isNull();
    var session = new MockHttpSession();
    assertThat(sessions.pending(session)).isNull();
    // The last instant of the window is already too late; the step is removed.
    session.setAttribute(
        PasswordSignInSession.PENDING,
        new PasswordSignInSession.Pending("priya@example.invalid", "EMAIL_OTP", "s", now, "/"));
    assertThat(sessions.pending(session)).isNull();
    assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isNull();
    var live =
        new PasswordSignInSession.Pending(
            "priya@example.invalid", "EMAIL_OTP", "s", now.plusMillis(1), "/");
    session.setAttribute(PasswordSignInSession.PENDING, live);
    assertThat(sessions.pending(session)).isSameAs(live);
    assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isSameAs(live);
    // Something else under the name is not a step; it is removed too.
    session.setAttribute(PasswordSignInSession.PENDING, "EMAIL_OTP");
    assertThat(sessions.pending(session)).isNull();
    assertThat(session.getAttribute(PasswordSignInSession.PENDING)).isNull();
  }
}
