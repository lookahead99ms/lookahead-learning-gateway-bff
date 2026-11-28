package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

/**
 * DLV-1015: what the callers of SignInDomainClient read from the session and hand to it (the client
 * no longer reads the session).
 */
class SignInProofSessionTest {
  @Test
  void theChallengeIsTheStringThisSessionHoldsAndNeverCreatesASession() {
    var request = new MockHttpServletRequest();
    assertThat(SignInProofSession.challenge(request)).isNull();
    assertThat(request.getSession(false)).isNull();
    request.getSession().setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
    assertThat(SignInProofSession.challenge(request)).isEqualTo("c".repeat(43));
    assertThat(SignInProofSession.restricted(request)).isTrue();
    // Anything that is not a string is no challenge, exactly as for restricted().
    request.getSession().setAttribute(SignInProofSession.CHALLENGE, Boolean.TRUE);
    assertThat(SignInProofSession.challenge(request)).isNull();
    assertThat(SignInProofSession.restricted(request)).isFalse();
    request.getSession().removeAttribute(SignInProofSession.CHALLENGE);
    assertThat(SignInProofSession.challenge(request)).isNull();
    // A browser header of the same name is never the challenge.
    var forged = new MockHttpServletRequest();
    forged.addHeader("X-LookAhead-Challenge", "attacker");
    assertThat(SignInProofSession.challenge(forged)).isNull();
  }

  @Test
  void theProofIsReadWithoutCreatingOneAndTheForwardersStillSendItInTheCloudOnly() {
    var request = new MockHttpServletRequest();
    assertThat(SignInProofSession.proof(request, false)).isNull();
    assertThat(request.getSession(false)).isNull();
    String proof = SignInProofSession.proof(request, true);
    assertThat(SignInProofSession.proof(request, false)).isEqualTo(proof);
    var cloud = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    var local =
        new OAuthClientDetails(
            "http://localhost",
            "test",
            "synthetic-secret",
            "http://identity",
            "http://domain",
            "http://localhost");
    var sent = new HttpHeaders();
    SignInProofSession.apply(cloud, request, sent);
    assertThat(sent.getFirst("X-LookAhead-SignIn-Proof")).isEqualTo(proof);
    var notSent = new HttpHeaders();
    SignInProofSession.apply(local, request, notSent);
    assertThat(notSent.isEmpty()).isTrue();
  }

  /**
   * DLV-1015: the one method that sets the proof header, for the clients that are handed the proof
   * as a value.
   */
  @Test
  void aProofHandedInAsAValueIsSentInTheCloudOnlyAndNeverWhenThereIsNone() {
    var cloud = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
    var local =
        new OAuthClientDetails(
            "http://localhost",
            "test",
            "synthetic-secret",
            "http://identity",
            "http://domain",
            "http://localhost");
    var sent = new HttpHeaders();
    SignInProofSession.apply(cloud, "synthetic-proof", sent);
    assertThat(sent.toSingleValueMap())
        .containsExactly(Map.entry("X-LookAhead-SignIn-Proof", "synthetic-proof"));
    assertThat(SignInProofSession.PROOF_HEADER).isEqualTo("X-LookAhead-SignIn-Proof");
    var none = new HttpHeaders();
    SignInProofSession.apply(cloud, (String) null, none);
    assertThat(none.isEmpty()).isTrue();
    var notSent = new HttpHeaders();
    SignInProofSession.apply(local, "synthetic-proof", notSent);
    assertThat(notSent.isEmpty()).isTrue();
  }
}
