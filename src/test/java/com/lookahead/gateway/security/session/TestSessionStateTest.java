package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/**
 * DLV-1015: the two session changes of a test session, driven directly (moved here from
 * TestSessionController, statements unchanged); the routes drive them in
 * TestSessionControllerIntegrationTest.
 */
class TestSessionStateTest {
  static final String LEARNER = "2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a",
      ANOTHER = "7f1d3b5a-9c2e-4a6b-8d0f-1e2c3b4a5d6e";

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  static OAuth2AuthenticationToken staff() {
    return new OAuth2AuthenticationToken(
        new DefaultOAuth2User(Set.of(), Map.of("sub", "synthetic-staff"), "sub"),
        Set.of(),
        "lookahead");
  }

  static SecurityContext saved(MockHttpServletRequest request) {
    return (SecurityContext) request.getSession(false).getAttribute("SPRING_SECURITY_CONTEXT");
  }

  @Test
  void startingWhileSignedOutMakesTheSessionATestSessionWithAFreshIdAndAnActivityStamp() {
    var request = new MockHttpServletRequest();
    request.getSession().setAttribute("syntheticGateAdmission", "kept");
    String before = request.getSession().getId();
    Instant earliest = Instant.now();
    TestSessionState.start(request, new MockHttpServletResponse(), null, UUID.fromString(LEARNER));
    var session = request.getSession(false);
    assertThat(session.getId()).isNotEqualTo(before);
    assertThat(session.getAttribute("syntheticGateAdmission")).isEqualTo("kept");
    assertThat(session.getAttribute(SignInSession.LAST_ACTIVITY)).isInstanceOf(Instant.class);
    assertThat((Instant) session.getAttribute("lookaheadLearnerActivity"))
        .isBetween(earliest, Instant.now());
    assertThat(session.getAttribute(TestSessionState.STAFF_SIGN_IN)).isNull();
    var signedIn = saved(request).getAuthentication();
    assertThat(TestSessionState.active(signedIn)).isTrue();
    assertThat(signedIn.getPrincipal()).isEqualTo(LEARNER);
    assertThat(signedIn.isAuthenticated()).isTrue();
    assertThat(SecurityContextHolder.getContext()).isSameAs(saved(request));
  }

  @Test
  void
      startingFromTheStaffSignInKeepsItAsideAndASwitchBetweenTestAccountsKeepsTheOneAlreadyThere() {
    var request = new MockHttpServletRequest();
    request.getSession();
    var staff = staff();
    TestSessionState.start(request, new MockHttpServletResponse(), staff, UUID.fromString(LEARNER));
    assertThat(request.getSession(false).getAttribute("lookaheadTestSessionStaffSignIn"))
        .isSameAs(staff);
    assertThat(TestSessionState.staffSignIn(request)).isSameAs(staff);
    var first = saved(request).getAuthentication();
    assertThat(first.getPrincipal()).isEqualTo(LEARNER);
    String between = request.getSession().getId();
    TestSessionState.start(request, new MockHttpServletResponse(), first, UUID.fromString(ANOTHER));
    assertThat(request.getSession().getId()).isNotEqualTo(between);
    assertThat(TestSessionState.staffSignIn(request)).isSameAs(staff);
    assertThat(saved(request).getAuthentication().getPrincipal()).isEqualTo(ANOTHER);
    assertThat(TestSessionState.active(SecurityContextHolder.getContext().getAuthentication()))
        .isTrue();
  }

  @Test
  void endingPutsTheStaffSignInBackWithAFreshIdAndNothingKeptAside() {
    var request = new MockHttpServletRequest();
    request.getSession();
    var staff = staff();
    TestSessionState.start(request, new MockHttpServletResponse(), staff, UUID.fromString(LEARNER));
    request.getSession().setAttribute("syntheticGateAdmission", "kept");
    String before = request.getSession().getId();
    TestSessionState.end(request, new MockHttpServletResponse(), staff);
    var session = request.getSession(false);
    assertThat(session.getId()).isNotEqualTo(before);
    assertThat(session.getAttribute(TestSessionState.STAFF_SIGN_IN)).isNull();
    assertThat(TestSessionState.staffSignIn(request)).isNull();
    assertThat(session.getAttribute("syntheticGateAdmission")).isEqualTo("kept");
    assertThat(saved(request).getAuthentication()).isSameAs(staff);
    assertThat(TestSessionState.active(saved(request).getAuthentication())).isFalse();
    assertThat(SecurityContextHolder.getContext()).isSameAs(saved(request));
  }

  @Test
  void aTestSessionIsAuthenticatedAsItsAccountAndCarriesNoCredentials() {
    var session = new TestSessionState.TestSession("test-account-7");
    assertThat(session.isAuthenticated()).isTrue();
    assertThat(session.getPrincipal()).isEqualTo("test-account-7");
    assertThat(session.getCredentials()).isNull();
    assertThat(session.getAuthorities()).isEmpty();
    assertThat(TestSessionState.active(session)).isTrue();
  }
}
