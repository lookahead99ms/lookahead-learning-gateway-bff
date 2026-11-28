package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.TestSessionState;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;
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
 * DLV-1015: the account-merge forwarder driven directly; the routes drive it in
 * GatewayBffApplicationCloudIntegrationTest.
 */
class AccountMergeProxyTest {
  private final OAuthClientDetails oauth =
      new OAuthClientDetails(
          "http://localhost",
          "test",
          "synthetic-secret",
          "http://identity",
          "http://domain",
          "http://localhost");
  private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
  private final OAuth2AuthorizedClientRepository clients =
      mock(OAuth2AuthorizedClientRepository.class);
  private final RestClient.Builder http = RestClient.builder();
  private final MockRestServiceServer domain = MockRestServiceServer.bindTo(http).build();
  private final AccountMergeProxy proxy =
      new AccountMergeProxy(oauth, new SignInTokenClient(manager), clients, http.build());

  @Test
  void aTestAccountOrAMissingSignInIsRefusedBeforeTheDomainIsAsked() throws Exception {
    var testAccount =
        proxy.forward(
            HttpMethod.POST,
            "/request",
            new MockHttpServletRequest("POST", "/api/v1/account/merge/request"),
            new MockHttpServletResponse(),
            new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
    assertThat(testAccount.getStatusCode().value()).isEqualTo(409);
    assertThat(testAccount.getBody()).isEqualTo(Map.of("code", "TEST_SESSION"));
    var signedOut =
        proxy.forward(
            HttpMethod.GET,
            "/" + "t".repeat(43),
            new MockHttpServletRequest("GET", "/api/v1/account/merge/" + "t".repeat(43)),
            new MockHttpServletResponse(),
            null);
    assertThat(signedOut.getStatusCode().value()).isEqualTo(401);
    assertThat(signedOut.getBody()).isEqualTo(Map.of("code", "AUTHENTICATION_REQUIRED"));
    assertThat(signedOut.getHeaders().getCacheControl()).isEqualTo("no-store");
    verifyNoInteractions(manager, clients);
    domain.verify();
  }

  @Test
  void aSignedInRequestGoesToTheDomainWithTheServerHeldTokenAndItsAnswerComesBackUnchanged()
      throws Exception {
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
    var authentication =
        new OAuth2AuthenticationToken(
            new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"),
            Set.of(),
            "lookahead");
    var request = new MockHttpServletRequest("POST", "/api/v1/account/merge/request");
    request.setContent("{}".getBytes());
    domain
        .expect(requestTo("http://domain/api/v1/account/merge/request"))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", "Bearer server-only-token"))
        .andExpect(headerDoesNotExist("Cookie"))
        .andExpect(content().string("{}"))
        .andRespond(
            withStatus(HttpStatus.ACCEPTED)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"data\":{}}"));
    var answer =
        proxy.forward(
            HttpMethod.POST, "/request", request, new MockHttpServletResponse(), authentication);
    domain.verify();
    assertThat(answer.getStatusCode().value()).isEqualTo(202);
    assertThat(new String((byte[]) answer.getBody())).isEqualTo("{\"data\":{}}");
    assertThat(answer.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
  }

  /**
   * DLV-1015: the merge forwarder's own answers and lines when the token cannot be renewed or the
   * call fails (the handling is shared with AccountCloudProxy).
   */
  @Test
  void aRefusedRefreshEndsTheSignInAndAnyOtherFailureIsUnavailableInTheMergeAnswerShape()
      throws Exception {
    var authentication =
        new OAuth2AuthenticationToken(
            new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"),
            Set.of(),
            "lookahead");
    try (var log = new LogCapture("lookahead.event")) {
      when(manager.authorize(any()))
          .thenThrow(
              new OAuth2AuthorizationException(
                  new OAuth2Error("invalid_grant", "private-provider-detail", null)));
      var request = new MockHttpServletRequest("GET", "/api/v1/account/merge/" + "t".repeat(43));
      var session = (MockHttpSession) request.getSession();
      var response = new MockHttpServletResponse();
      var expired =
          proxy.forward(HttpMethod.GET, "/" + "t".repeat(43), request, response, authentication);
      assertThat(expired.getStatusCode().value()).isEqualTo(401);
      assertThat(expired.getBody()).isEqualTo(Map.of("code", "AUTHENTICATION_REQUIRED"));
      assertThat(expired.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
      assertThat(expired.getHeaders().getCacheControl()).isEqualTo("no-store");
      assertThat(session.isInvalid()).isTrue();
      verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
      assertThat(log.messages())
          .containsExactly(
              "Merge step merge.candidates refused: AUTHENTICATION_REQUIRED (session expired:"
                  + " Cognito refused the refresh token (invalid_grant))");
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=merge.candidates",
              "event.outcome=refused",
              "reason=AUTHENTICATION_REQUIRED",
              "http.status=401");
      log.clear();
      // Any other refresh failure keeps the sign-in.
      Mockito.reset(manager);
      when(manager.authorize(any()))
          .thenThrow(
              new OAuth2AuthorizationException(
                  new OAuth2Error("temporarily_unavailable", "private-provider-detail", null)));
      var kept = new MockHttpServletRequest("POST", "/api/v1/account/merge/request");
      kept.setContent("{}".getBytes());
      kept.getSession();
      var unavailable =
          proxy.forward(
              HttpMethod.POST, "/request", kept, new MockHttpServletResponse(), authentication);
      assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
      assertThat(unavailable.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
      assertThat(((MockHttpSession) kept.getSession(false)).isInvalid()).isFalse();
      assertThat(log.messages())
          .containsExactly(
              "Merge step merge.request refused: SERVICE_UNAVAILABLE (the token refresh did not"
                  + " succeed)");
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=merge.request",
              "event.outcome=failure",
              "reason=SERVICE_UNAVAILABLE",
              "http.status=503");
      log.clear();
      Mockito.reset(manager);
      when(manager.authorize(any())).thenThrow(new IllegalStateException("private detail"));
      var failed =
          proxy.forward(
              HttpMethod.POST,
              "/" + "t".repeat(43),
              new MockHttpServletRequest("POST", "/api/v1/account/merge/" + "t".repeat(43)),
              new MockHttpServletResponse(),
              authentication);
      assertThat(failed.getStatusCode().value()).isEqualTo(503);
      assertThat(failed.getBody()).isEqualTo(Map.of("code", "SERVICE_UNAVAILABLE"));
      assertThat(log.messages())
          .containsExactly(
              "Merge step merge.merge refused: SERVICE_UNAVAILABLE (Domain did not answer"
                  + " (IllegalStateException))");
      log.assertNothing("private");
    }
    verify(clients, Mockito.times(1)).removeAuthorizedClient(any(), any(), any(), any());
    domain.verify();
  }

  // DLV-1015: the shape check of the emailed token, moved here from AccountMergeProxyController
  // (statement unchanged).

  @Test
  void aTokenOfAnotherShapeIsAnswered404BeforeAnyOtherCheckWithoutALogLineOrACall()
      throws Exception {
    assertThat(AccountMergeProxy.TOKEN).isEqualTo("[A-Za-z0-9_-]{43}");
    try (var log = new LogCapture("lookahead.event")) {
      for (String bad :
          new String[] {
            "",
            "t".repeat(42),
            "t".repeat(44),
            "t".repeat(42) + "+",
            "t".repeat(42) + "/",
            "request",
            "t".repeat(42) + "\n"
          }) {
        for (HttpMethod method : new HttpMethod[] {HttpMethod.GET, HttpMethod.POST}) {
          // Nobody is signed in and the session is a test session's: the token is still looked at
          // first.
          for (var authentication :
              new Authentication[] {
                null, new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a")
              }) {
            var request = new MockHttpServletRequest(method.name(), "/api/v1/account/merge/" + bad);
            request.setContent(new byte[AccountMergeProxy.MAX_BODY + 1]);
            var answer =
                proxy.forwardWithToken(
                    method, bad, request, new MockHttpServletResponse(), authentication);
            assertThat(answer.getStatusCode().value()).as(bad).isEqualTo(404);
            assertThat(answer.getBody()).isEqualTo(Map.of("code", "MERGE_TOKEN_INVALID"));
            assertThat(answer.getHeaders().getCacheControl()).isEqualTo("no-store");
            assertThat(answer.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
            assertThat(request.getInputStream().readAllBytes())
                .hasSize(AccountMergeProxy.MAX_BODY + 1);
          }
        }
      }
      assertThat(log.lines()).isEmpty();
    }
    verifyNoInteractions(manager, clients);
    domain.verify();
  }

  @Test
  void aWellFormedTokenIsForwardedAsThePathAndTheOtherRefusalsThenApply() throws Exception {
    String token = "Aa0_-" + "t".repeat(38);
    var signedOut =
        proxy.forwardWithToken(
            HttpMethod.GET,
            token,
            new MockHttpServletRequest("GET", "/api/v1/account/merge/" + token),
            new MockHttpServletResponse(),
            null);
    assertThat(signedOut.getStatusCode().value()).isEqualTo(401);
    assertThat(signedOut.getBody()).isEqualTo(Map.of("code", "AUTHENTICATION_REQUIRED"));
    verifyNoInteractions(manager, clients);
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
    var authentication =
        new OAuth2AuthenticationToken(
            new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"),
            Set.of(),
            "lookahead");
    domain
        .expect(requestTo("http://domain/api/v1/account/merge/" + token))
        .andExpect(method(HttpMethod.GET))
        .andExpect(header("Authorization", "Bearer server-only-token"))
        .andRespond(
            withStatus(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"data\":{\"accounts\":[]}}"));
    var request = new MockHttpServletRequest("POST", "/api/v1/account/merge/" + token);
    request.setContent("{}".getBytes());
    domain
        .expect(requestTo("http://domain/api/v1/account/merge/" + token))
        .andExpect(method(HttpMethod.POST))
        .andExpect(content().string("{}"))
        .andRespond(
            withStatus(HttpStatus.OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body("{\"data\":{}}"));
    var candidates =
        proxy.forwardWithToken(
            HttpMethod.GET,
            token,
            new MockHttpServletRequest("GET", "/api/v1/account/merge/" + token),
            new MockHttpServletResponse(),
            authentication);
    assertThat(candidates.getStatusCode().value()).isEqualTo(200);
    assertThat(new String((byte[]) candidates.getBody())).isEqualTo("{\"data\":{\"accounts\":[]}}");
    assertThat(
            proxy
                .forwardWithToken(
                    HttpMethod.POST, token, request, new MockHttpServletResponse(), authentication)
                .getStatusCode()
                .value())
        .isEqualTo(200);
    domain.verify();
  }
}
