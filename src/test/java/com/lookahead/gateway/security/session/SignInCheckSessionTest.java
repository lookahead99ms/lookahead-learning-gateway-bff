package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.web.util.WebUtils;

/**
 * DLV-1015: the passed sign-in check a session remembers, driven directly: for whom, for how long,
 * and what an ended session answers. The filter that asks the Domain and uses this memory is in
 * SignInCheckFilterTest.
 */
class SignInCheckSessionTest {
  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void advance(long seconds) {
      now = now.plusSeconds(seconds);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  final MutableClock clock = new MutableClock(Instant.parse("2026-11-02T20:00:00Z"));
  final SignInCheckSession checks = new SignInCheckSession(clock);

  @Test
  void aPassedCheckIsRememberedForThatPersonForOneMinuteAndNoLonger() {
    var session = new MockHttpSession();
    assertThat(checks.passedRecently(session, "synthetic-subject")).isFalse();
    assertThat(checks.remember(session, "synthetic-subject")).isTrue();
    // What the session holds: one value under the one name, the person and the moment.
    assertThat(SignInCheckSession.CHECKED).isEqualTo("lookaheadSignInChecked");
    assertThat(SignInCheckSession.REUSE).isEqualTo(Duration.ofSeconds(60));
    assertThat(session.getAttribute("lookaheadSignInChecked"))
        .isEqualTo(new SignInCheckSession.Checked("synthetic-subject", clock.instant()));
    assertThat(checks.passedRecently(session, "synthetic-subject")).isTrue();
    // Only for the person who passed it.
    assertThat(checks.passedRecently(session, "another-subject")).isFalse();
    assertThat(checks.passedRecently(session, null)).isFalse();
    clock.advance(59);
    assertThat(checks.passedRecently(session, "synthetic-subject")).isTrue();
    clock.advance(1);
    assertThat(checks.passedRecently(session, "synthetic-subject")).isFalse();
    // A new passed check starts a new minute and replaces the old one.
    assertThat(checks.remember(session, "synthetic-subject")).isTrue();
    clock.advance(59);
    assertThat(checks.passedRecently(session, "synthetic-subject")).isTrue();
    assertThat(checks.remember(session, "another-subject")).isTrue();
    assertThat(checks.passedRecently(session, "synthetic-subject")).isFalse();
    assertThat(checks.passedRecently(session, "another-subject")).isTrue();
  }

  @Test
  void anythingElseUnderTheNameIsNotAPassedCheck() {
    var session = new MockHttpSession();
    for (Object other : new Object[] {"synthetic-subject", Boolean.TRUE, clock.instant()}) {
      session.setAttribute(SignInCheckSession.CHECKED, other);
      assertThat(checks.passedRecently(session, "synthetic-subject"))
          .as(String.valueOf(other))
          .isFalse();
    }
  }

  @Test
  void anEndedSessionAnswersNeitherYesNorNoAndRemembersNothing() {
    var session = new MockHttpSession();
    assertThat(checks.remember(session, "synthetic-subject")).isTrue();
    session.invalidate();
    assertThat(checks.passedRecently(session, "synthetic-subject")).isNull();
    assertThat(checks.remember(session, "synthetic-subject")).isFalse();
  }

  @Test
  void theLockIsTheSessionsOwnAndARequestWithoutASessionLocksOnItsOwn() {
    var session = new MockHttpSession();
    // Without a mutex attribute Spring's session mutex is the session itself.
    assertThat(SignInCheckSession.mutex(session))
        .isSameAs(session)
        .isSameAs(SignInCheckSession.mutex(session));
    var mutex = new Object();
    session.setAttribute(WebUtils.SESSION_MUTEX_ATTRIBUTE, mutex);
    assertThat(SignInCheckSession.mutex(session)).isSameAs(mutex);
    // An ended session cannot be asked for its mutex: the session object itself is the lock.
    session.invalidate();
    assertThat(SignInCheckSession.mutex(session)).isSameAs(session);
    // No session: a lock of its own each time, shared with nobody.
    assertThat(SignInCheckSession.mutex(null))
        .isNotNull()
        .isNotSameAs(SignInCheckSession.mutex(null));
  }
}
