package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.AccountMergeOffer;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * DLV-1015: the cloud account forwarder driven directly (moved here from AccountCloudController,
 * statements unchanged); the routes drive it in AccountCloudControllerTest and
 * GatewayBffApplicationCloudIntegrationTest.
 */
class AccountCloudProxyTest {
  private final OAuthClientDetails oauth =
      OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
  private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
  private final OAuth2AuthorizedClientRepository clients =
      mock(OAuth2AuthorizedClientRepository.class);
  private final RestClient.Builder http = RestClient.builder();
  private final MockRestServiceServer domain = MockRestServiceServer.bindTo(http).build();
  private final AccountCloudProxy proxy =
      new AccountCloudProxy(
          new SignInTokenClient(manager), clients, new SignInDomainClient(oauth, http.build()));
  private final OAuth2AuthenticationToken authentication =
      new OAuth2AuthenticationToken(
          new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead");

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private void tokens() {
    var registration =
        ClientRegistration.withRegistrationId("lookahead")
            .clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize")
            .tokenUri("http://localhost/token")
            .build();
    when(manager.authorize(any()))
        .thenReturn(
            new OAuth2AuthorizedClient(
                registration,
                "account",
                new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    "server-only-token",
                    Instant.now(),
                    Instant.now().plusSeconds(300))));
  }

  /** The one call the next request may make; what was expected before must have been made. */
  private void domain(HttpMethod method, String action, HttpStatus status, String json) {
    domain.verify();
    domain.reset();
    domain
        .expect(requestTo(oauth.domainApiUpstream() + "/internal/v1/cloud-sign-ins/" + action))
        .andExpect(method(method))
        .andExpect(header("Authorization", "Bearer server-only-token"))
        .andExpect(header("X-LookAhead-Gateway-Secret", oauth.domainSecret()))
        .andRespond(withStatus(status).contentType(MediaType.APPLICATION_JSON).body(json));
  }

  private static MockHttpServletRequest request(String method, String path) {
    var request = new MockHttpServletRequest(method, path);
    request.setSession(new MockHttpSession());
    return request;
  }

  @Test
  void aSessionAtTheSignInChallengeOrATestAccountIsRefusedBeforeAnyoneIsAsked() {
    try (var log = new LogCapture("lookahead.event")) {
      var restricted = request("GET", "/api/v1/account/profile");
      restricted.getSession().setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
      var challenge =
          proxy.forward(restricted, new MockHttpServletResponse(), authentication, null);
      assertThat(challenge.getStatusCode().value()).isEqualTo(401);
      assertThat(challenge.getBody())
          .isEqualTo(
              Map.of(
                  "code",
                  "SIGN_IN_CHALLENGE_REQUIRED",
                  "message",
                  "Choose an active sign-in to continue."));
      assertThat(challenge.getHeaders().getCacheControl()).isEqualTo("no-store");
      assertThat(log.messages())
          .containsExactly(
              "Account request account.profile refused: SIGN_IN_CHALLENGE_REQUIRED (the person must"
                  + " first choose which active sign-in to end)");
      assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=account.profile",
              "event.outcome=refused",
              "reason=SIGN_IN_CHALLENGE_REQUIRED",
              "http.status=401");
      log.clear();
      var testAccount =
          proxy.forward(
              request("POST", "/api/v1/account/password"),
              new MockHttpServletResponse(),
              new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"),
              Map.of("password", "synthetic"));
      assertThat(testAccount.getStatusCode().value()).isEqualTo(409);
      assertThat(testAccount.getBody())
          .isEqualTo(
              Map.of(
                  "code",
                  "TEST_SESSION",
                  "message",
                  "Test accounts have no sign-in, profile or password of their own."));
      assertThat(log.messages())
          .containsExactly(
              "Account request account.password refused: TEST_SESSION (a test account has no"
                  + " sign-in, profile or password of its own)");
      log.assertNothing("synthetic");
    }
    verifyNoInteractions(manager, clients);
    domain.verify();
  }

  @Test
  void theDomainActionIsTheLastPathSegmentWithTwoRenamesAndAReadIsNotLoggedWhenItSucceeds() {
    tokens();
    try (var log = new LogCapture("lookahead.event")) {
      domain(HttpMethod.GET, "inventory", HttpStatus.OK, "{\"data\":{\"signIns\":[]}}");
      var inventory =
          proxy.forward(
              request("GET", "/api/v1/account/sign-ins"),
              new MockHttpServletResponse(),
              authentication,
              null);
      assertThat(inventory.getStatusCode().value()).isEqualTo(200);
      assertThat(new String((byte[]) inventory.getBody())).isEqualTo("{\"data\":{\"signIns\":[]}}");
      assertThat(inventory.getHeaders().getCacheControl()).isEqualTo("no-store");
      assertThat(inventory.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
      // A session at the sign-in challenge may still read and answer its challenge.
      var restricted = request("GET", "/api/v1/auth/sign-in-challenge");
      restricted.getSession().setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
      domain.verify();
      domain.reset();
      domain
          .expect(requestTo(oauth.domainApiUpstream() + "/internal/v1/cloud-sign-ins/challenge"))
          .andExpect(method(HttpMethod.GET))
          .andExpect(header("X-LookAhead-Challenge", "c".repeat(43)))
          .andRespond(
              withStatus(HttpStatus.OK)
                  .contentType(MediaType.APPLICATION_JSON)
                  .body("{\"data\":{}}"));
      assertThat(
              proxy
                  .forward(restricted, new MockHttpServletResponse(), authentication, null)
                  .getStatusCode()
                  .value())
          .isEqualTo(200);
      assertThat(log.messages()).isEmpty();
      // A change is logged as account.<action>, with whether the sign-in ends.
      domain.verify();
      domain.reset();
      domain
          .expect(requestTo(oauth.domainApiUpstream() + "/internal/v1/cloud-sign-ins/label"))
          .andExpect(method(HttpMethod.POST))
          .andExpect(content().json("{\"label\":\"Laptop\"}"))
          .andRespond(
              withStatus(HttpStatus.OK)
                  .contentType(MediaType.APPLICATION_JSON)
                  .body("{\"data\":{}}"));
      var request = request("POST", "/api/v1/account/sign-ins/label");
      assertThat(
              proxy
                  .forward(
                      request,
                      new MockHttpServletResponse(),
                      authentication,
                      Map.of("label", "Laptop"))
                  .getStatusCode()
                  .value())
          .isEqualTo(200);
      assertThat(log.messages()).containsExactly("Account action label done");
      assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=account.label", "event.outcome=success", "signIn.ended=false");
      assertThat(request.getSession(false)).isNotNull();
    }
    verifyNoInteractions(clients);
    domain.verify();
  }

  @Test
  void aDomainRefusalKeepsItsStatusAndBodyAndADomainFailureIsAnswered503() {
    tokens();
    try (var log = new LogCapture("lookahead.event")) {
      domain(
          HttpMethod.POST,
          "password",
          HttpStatus.CONFLICT,
          "{\"code\":\"PASSWORD_REUSED\",\"message\":\"synthetic Domain words\"}");
      var refused =
          proxy.forward(
              request("POST", "/api/v1/account/password"),
              new MockHttpServletResponse(),
              authentication,
              Map.of("password", "synthetic-secret"));
      assertThat(refused.getStatusCode().value()).isEqualTo(409);
      assertThat(new String((byte[]) refused.getBody()))
          .isEqualTo("{\"code\":\"PASSWORD_REUSED\",\"message\":\"synthetic Domain words\"}");
      assertThat(refused.getHeaders().getCacheControl()).isEqualTo("no-store");
      assertThat(refused.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
      assertThat(log.messages())
          .containsExactly("Account action password refused by Domain: PASSWORD_REUSED (HTTP 409)");
      assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=account.password",
              "event.outcome=refused",
              "reason=PASSWORD_REUSED",
              "upstream.status=409");
      log.clear();
      domain(HttpMethod.GET, "profile", HttpStatus.BAD_GATEWAY, "{}");
      var failed =
          proxy.forward(
              request("GET", "/api/v1/account/profile"),
              new MockHttpServletResponse(),
              authentication,
              null);
      assertThat(failed.getStatusCode().value()).isEqualTo(503);
      assertThat(new String((byte[]) failed.getBody())).isEqualTo("{}");
      assertThat(log.messages())
          .containsExactly("Account action profile refused by Domain: HTTP_502 (HTTP 502)");
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=account.profile",
              "event.outcome=failure",
              "reason=HTTP_502",
              "upstream.status=502");
      log.assertNothing("synthetic-secret", "synthetic Domain words");
    }
    verifyNoInteractions(clients);
    domain.verify();
  }

  @Test
  void replacingASignInAnswersWithTheOwnerAndKeepsTheMergeOfferOnlyWhenTheDomainSaidTrue() {
    tokens();
    var request = request("POST", "/api/v1/auth/sign-in-challenge/replace");
    request.getSession().setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
    domain(
        HttpMethod.POST,
        "replace",
        HttpStatus.OK,
        "{\"data\":{\"accountId\":\"owner-1\",\"mergeAvailable\":true}}");
    var offered =
        proxy.forward(
            request, new MockHttpServletResponse(), authentication, Map.of("signInId", "s-1"));
    assertThat(offered.getStatusCode().value()).isEqualTo(200);
    assertThat(offered.getHeaders().getCacheControl()).isEqualTo("no-store");
    var expected = new LinkedHashMap<String, Object>();
    expected.put("accountId", "owner-1");
    expected.put("mergeAvailable", true);
    assertThat(((ApiResponse<?>) offered.getBody()).data()).isEqualTo(expected);
    assertThat(request.getSession().getAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE))
        .isEqualTo(Boolean.TRUE);
    assertThat(request.getSession().getAttribute("lookaheadMergeAfterChallenge"))
        .isEqualTo(Boolean.TRUE);
    // Anything but a literal true takes the offer away again.
    domain(
        HttpMethod.POST,
        "replace",
        HttpStatus.OK,
        "{\"data\":{\"accountId\":\"owner-1\",\"mergeAvailable\":\"true\"}}");
    var plain =
        proxy.forward(
            request, new MockHttpServletResponse(), authentication, Map.of("signInId", "s-1"));
    assertThat(((ApiResponse<?>) plain.getBody()).data()).isEqualTo(Map.of("accountId", "owner-1"));
    assertThat(request.getSession().getAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE)).isNull();
    // No owner in the answer: nothing to bind a retry to.
    domain(HttpMethod.POST, "replace", HttpStatus.OK, "{\"data\":{}}");
    var ownerless =
        proxy.forward(
            request, new MockHttpServletResponse(), authentication, Map.of("signInId", "s-1"));
    assertThat(ownerless.getStatusCode().value()).isEqualTo(503);
    assertThat(ownerless.getBody())
        .isEqualTo(
            Map.of(
                "code",
                "SERVICE_UNAVAILABLE",
                "message",
                "Sign-in service is unavailable. Retry shortly."));
    assertThat(((MockHttpSession) request.getSession(false)).isInvalid()).isFalse();
    verifyNoInteractions(clients);
    domain.verify();
  }

  @Test
  void anActionThatEndsTheSignInRemovesTheTokensAndTheSession() {
    tokens();
    try (var log = new LogCapture("lookahead.event")) {
      for (var ending :
          Map.of(
                  "/api/v1/auth/sign-in-challenge/cancel",
                  "{\"data\":{}}",
                  "/api/v1/account/password",
                  "{\"data\":{\"reauthenticationRequired\":true}}")
              .entrySet()) {
        String action = ending.getKey().substring(ending.getKey().lastIndexOf('/') + 1);
        var request = request("POST", ending.getKey());
        var session = (MockHttpSession) request.getSession();
        var response = new MockHttpServletResponse();
        domain(HttpMethod.POST, action, HttpStatus.OK, ending.getValue());
        var done = proxy.forward(request, response, authentication, Map.of());
        assertThat(done.getStatusCode().value()).isEqualTo(200);
        assertThat(new String((byte[]) done.getBody())).isEqualTo(ending.getValue());
        assertThat(session.isInvalid()).as(action).isTrue();
        verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
        assertThat(log.last().getFormattedMessage())
            .isEqualTo(
                "Account action "
                    + action
                    + " done; this sign-in ends and the person signs in again");
        assertThat(LogCapture.pairs(log.last()))
            .containsExactly(
                "event.action=account." + action, "event.outcome=success", "signIn.ended=true");
        domain.verify();
      }
    }
  }

  @Test
  void withoutUsableProviderTokensNothingIsSentToTheDomain() {
    try (var log = new LogCapture("lookahead.event")) {
      var none =
          proxy.forward(
              request("GET", "/api/v1/account/profile"),
              new MockHttpServletResponse(),
              authentication,
              null);
      assertThat(none.getStatusCode().value()).isEqualTo(401);
      assertThat(none.getBody())
          .isEqualTo(
              Map.of("code", "AUTHENTICATION_REQUIRED", "message", "Sign in again to continue."));
      assertThat(log.messages())
          .containsExactly(
              "Account request account.profile refused: AUTHENTICATION_REQUIRED (this session holds"
                  + " no provider tokens)");
      verifyNoInteractions(clients);
      log.clear();
      // Cognito refused the refresh token: the sign-in is over.
      doThrow(
              new OAuth2AuthorizationException(
                  new OAuth2Error("invalid_grant", "private-provider-detail", null)))
          .when(manager)
          .authorize(any());
      var request = request("GET", "/api/v1/account/sign-ins");
      var session = (MockHttpSession) request.getSession();
      var response = new MockHttpServletResponse();
      var expired = proxy.forward(request, response, authentication, null);
      assertThat(expired.getStatusCode().value()).isEqualTo(401);
      assertThat(expired.getBody())
          .isEqualTo(
              Map.of("code", "AUTHENTICATION_REQUIRED", "message", "Sign in again to continue."));
      assertThat(session.isInvalid()).isTrue();
      verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
      assertThat(log.messages())
          .containsExactly(
              "Account request account.inventory refused: AUTHENTICATION_REQUIRED (session expired:"
                  + " Cognito refused the refresh token (invalid_grant))");
      log.clear();
      // Any other refresh failure keeps the sign-in.
      doThrow(
              new OAuth2AuthorizationException(
                  new OAuth2Error("temporarily_unavailable", "private-provider-detail", null)))
          .when(manager)
          .authorize(any());
      var kept = request("GET", "/api/v1/account/sign-ins");
      var unavailable = proxy.forward(kept, new MockHttpServletResponse(), authentication, null);
      assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
      assertThat(unavailable.getBody())
          .isEqualTo(
              Map.of(
                  "code",
                  "SERVICE_UNAVAILABLE",
                  "message",
                  "Sign-in service is unavailable. Retry shortly."));
      assertThat(((MockHttpSession) kept.getSession(false)).isInvalid()).isFalse();
      assertThat(log.messages())
          .containsExactly(
              "Account request account.inventory refused: SERVICE_UNAVAILABLE (the token refresh"
                  + " did not succeed)");
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=account.inventory",
              "event.outcome=failure",
              "reason=SERVICE_UNAVAILABLE",
              "http.status=503");
      log.clear();
      doThrow(new IllegalStateException("private detail")).when(manager).authorize(any());
      var failed =
          proxy.forward(
              request("GET", "/api/v1/account/profile"),
              new MockHttpServletResponse(),
              authentication,
              null);
      assertThat(failed.getStatusCode().value()).isEqualTo(503);
      assertThat(log.messages())
          .containsExactly(
              "Account request account.profile refused: SERVICE_UNAVAILABLE (Domain did not answer"
                  + " (IllegalStateException))");
      log.assertNothing("private-provider-detail", "private detail");
    }
    domain.verify();
  }
}
