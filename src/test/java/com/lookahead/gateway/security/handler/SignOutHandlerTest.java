package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.client.SignInCognitoClient;
import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInIdentityClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * DLV-1015: the sign-out code driven directly. It moved here, statements unchanged, from
 * SignInController (Sign out and the redirect that finishes a cloud sign-out) and from
 * DevAccessController.leave (leaving DEV). The routes drive it in
 * GatewayBffApplicationCloudIntegrationTest, TestSessionControllerIntegrationTest,
 * GatewayBffApplicationLowerCostDevIntegrationTest and DevAccessControllerTest.
 */
class SignOutHandlerTest {
  private static final OAuthClientDetails CLOUD =
      OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
  private static final OAuthClientDetails LOCAL =
      new OAuthClientDetails(
          "http://127.0.0.1:4350",
          "lookahead-test",
          "synthetic-client-secret-only-for-testing",
          "http://identity:8080",
          "http://domain-api:8080",
          "http://127.0.0.1:4350");
  private static final String DOMAIN_LOGOUT =
      CLOUD.domainApiUpstream() + "/internal/v1/cloud-sign-ins/logout";
  private static final String COGNITO_REVOKE = CLOUD.managedLogin() + "/oauth2/revoke";

  private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
  private final OAuth2AuthorizedClientRepository clients =
      mock(OAuth2AuthorizedClientRepository.class);
  private final RestClient.Builder http = RestClient.builder();
  private final MockRestServiceServer upstream = MockRestServiceServer.bindTo(http).build();

  /**
   * What happened, in order: the token renewal, each outside call, and the tokens being dropped.
   */
  private final List<String> order = new ArrayList<>();

  private final OAuth2AuthenticationToken authentication =
      new OAuth2AuthenticationToken(
          new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead");

  @AfterEach
  void clear() {
    SecurityContextHolder.clearContext();
  }

  private SignOutHandler handler(OAuthClientDetails oauth) {
    return handler(oauth, devEnvironment());
  }

  private SignOutHandler handler(OAuthClientDetails oauth, MockEnvironment environment) {
    var rest = http.build();
    doAnswer(
            call -> {
              order.add("tokens dropped");
              return null;
            })
        .when(clients)
        .removeAuthorizedClient(any(), any(), any(), any());
    return new SignOutHandler(
        oauth,
        new SignInTokenClient(manager),
        clients,
        new SignInDomainClient(oauth, rest),
        new SignInIdentityClient(oauth, rest),
        new SignInCognitoClient(oauth, rest),
        environment);
  }

  private static MockEnvironment devEnvironment() {
    return new MockEnvironment()
        .withProperty("app.oauth.frontend", "https://dev.example.com")
        .withProperty(
            "app.cognito.managed-login", "https://learner.auth.us-east-2.amazoncognito.com")
        .withProperty("app.oauth.client-id", "learner-client");
  }

  private static OAuth2AuthorizedClient tokens(String access, String refresh) {
    var registration =
        ClientRegistration.withRegistrationId("lookahead")
            .clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize")
            .tokenUri("http://localhost/token")
            .build();
    return new OAuth2AuthorizedClient(
        registration,
        "account",
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            access,
            Instant.now(),
            Instant.now().plusSeconds(300)),
        refresh == null ? null : new OAuth2RefreshToken(refresh, Instant.now()));
  }

  /**
   * The renewal answers with these tokens (null: the session holds none) and is recorded with what
   * it was asked.
   */
  private List<OAuth2AuthorizeRequest> renewalAnswers(OAuth2AuthorizedClient client) {
    var asked = new ArrayList<OAuth2AuthorizeRequest>();
    doAnswer(
            call -> {
              order.add("tokens renewed");
              asked.add(call.getArgument(0));
              return client;
            })
        .when(manager)
        .authorize(any());
    return asked;
  }

  private void domainAnswers(HttpStatus status, String json) {
    upstream
        .expect(requestTo(DOMAIN_LOGOUT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", "Bearer server-only-token"))
        .andExpect(header("X-LookAhead-Gateway-Secret", CLOUD.domainSecret()))
        .andExpect(content().json("{}"))
        .andRespond(request -> {
          order.add("domain");
          return withStatus(status)
              .contentType(MediaType.APPLICATION_JSON)
              .body(json)
              .createResponse(request);
        });
  }

  private void cognitoAnswers(HttpStatus status, String refreshToken) {
    var basic = new HttpHeaders();
    basic.setBasicAuth(CLOUD.clientId(), CLOUD.clientSecret());
    upstream
        .expect(requestTo(COGNITO_REVOKE))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", basic.getFirst("Authorization")))
        .andExpect(content().string("token=" + refreshToken + "&token_type_hint=refresh_token"))
        .andRespond(request -> {
          order.add("cognito");
          return withStatus(status).createResponse(request);
        });
  }

  private static MockHttpServletRequest signOutRequest() {
    var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/logout");
    request.setSession(new MockHttpSession());
    return request;
  }

  @Test
  void localSignOutRevokesBothTokensAtTheIdentityServiceDropsThemAndNamesTheIdentityLogoutPage() {
    var handler = handler(LOCAL);
    var idToken =
        new OidcIdToken(
            "id.token+value/=",
            Instant.now(),
            Instant.now().plusSeconds(300),
            Map.of("sub", "account"));
    var signedIn =
        new OAuth2AuthenticationToken(
            new DefaultOidcUser(List.of(new OidcUserAuthority(idToken)), idToken, "sub"),
            Set.of(),
            "lookahead");
    var request = signOutRequest();
    var response = new MockHttpServletResponse();
    var old = (MockHttpSession) request.getSession();
    var admission = new DevAccessSession.State("tester", "admission", Instant.now());
    old.setAttribute(DevAccessSession.ATTRIBUTE, admission);
    when(clients.loadAuthorizedClient("lookahead", signedIn, request))
        .thenReturn(tokens("local-access", "local+refresh"));
    var basic = new HttpHeaders();
    basic.setBasicAuth(LOCAL.clientId(), LOCAL.clientSecret());
    for (String form : List.of("token=local-access", "token=local%2Brefresh"))
      upstream
          .expect(requestTo("http://identity:8080/oauth2/revoke"))
          .andExpect(method(HttpMethod.POST))
          .andExpect(header("Authorization", basic.getFirst("Authorization")))
          .andExpect(content().string(form))
          .andRespond(sent -> {
            order.add("identity " + form);
            return withStatus(HttpStatus.OK).createResponse(sent);
          });

    var answer = handler.logout(request, response, signedIn);

    assertThat(order)
        .containsExactly(
            "identity token=local-access", "identity token=local%2Brefresh", "tokens dropped");
    verify(clients).removeAuthorizedClient("lookahead", signedIn, request, response);
    assertThat(answer.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "http://127.0.0.1:4350/connect/logout?post_logout_redirect_uri="
                    + "http%3A%2F%2F127.0.0.1%3A4350%2Fsign-in"
                    + "&id_token_hint=id.token%2Bvalue%2F%3D"));
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    // The learner sign-in ends with its session; a DEV gate admission is carried into the new one.
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false).getAttribute(DevAccessSession.ATTRIBUTE))
        .isSameAs(admission);
    verifyNoInteractions(manager);
    upstream.verify();
  }

  @Test
  void localSignOutWithoutTokensOrAnIdTokenAsksNobodyAndSendsNoHint() {
    var handler = handler(LOCAL);
    var request = signOutRequest();
    var response = new MockHttpServletResponse();
    var old = (MockHttpSession) request.getSession();
    // An access token alone: one revocation, no second request for a refresh token that does not
    // exist.
    var accessOnly = signOutRequest();
    when(clients.loadAuthorizedClient("lookahead", authentication, accessOnly))
        .thenReturn(tokens("local-access", null));
    upstream
        .expect(requestTo("http://identity:8080/oauth2/revoke"))
        .andExpect(content().string("token=local-access"))
        .andRespond(withStatus(HttpStatus.OK));
    handler.logout(accessOnly, new MockHttpServletResponse(), authentication);
    upstream.verify();
    upstream.reset();
    order.clear();

    var answer = handler.logout(request, response, authentication);

    assertThat(answer.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "http://127.0.0.1:4350/connect/logout"
                    + "?post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A4350%2Fsign-in"));
    assertThat(order).containsExactly("tokens dropped");
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false)).isNull();
    upstream.verify();
  }

  @Test
  void anIdentityServiceThatRefusesTheRevocationStopsTheLocalSignOutBeforeTheTokensAreDropped() {
    var handler = handler(LOCAL);
    var request = signOutRequest();
    when(clients.loadAuthorizedClient("lookahead", authentication, request))
        .thenReturn(tokens("local-access", "local-refresh"));
    upstream
        .expect(requestTo("http://identity:8080/oauth2/revoke"))
        .andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
    assertThatThrownBy(() -> handler.logout(request, new MockHttpServletResponse(), authentication))
        .isInstanceOf(RestClientException.class);
    verify(clients, never()).removeAuthorizedClient(any(), any(), any(), any());
    assertThat(((MockHttpSession) request.getSession(false)).isInvalid()).isFalse();
    upstream.verify();
  }

  @Test
  void cloudSignOutRenewsTheTokensAsksTheDomainThenCognitoAndDropsTheTokens() {
    var handler = handler(CLOUD);
    var request = signOutRequest();
    var response = new MockHttpServletResponse();
    var old = (MockHttpSession) request.getSession();
    String proof = SignInProofSession.proof(request, true);
    old.setAttribute(SignInProofSession.CHALLENGE, "c".repeat(43));
    var asked = renewalAnswers(tokens("server-only-token", "server+refresh"));
    upstream
        .expect(requestTo(DOMAIN_LOGOUT))
        .andExpect(method(HttpMethod.POST))
        .andExpect(header("Authorization", "Bearer server-only-token"))
        .andExpect(header("X-LookAhead-Gateway-Secret", CLOUD.domainSecret()))
        .andExpect(header("X-LookAhead-SignIn-Proof", proof))
        .andExpect(header("X-LookAhead-Challenge", "c".repeat(43)))
        .andExpect(headerDoesNotExist("Cookie"))
        .andExpect(content().json("{}"))
        .andRespond(sent -> {
          order.add("domain");
          return withStatus(HttpStatus.OK)
              .contentType(MediaType.APPLICATION_JSON)
              .body("{\"data\":{}}")
              .createResponse(sent);
        });
    cognitoAnswers(HttpStatus.OK, "server%2Brefresh");

    var answer = handler.logout(request, response, authentication);

    assertThat(order).containsExactly("tokens renewed", "domain", "cognito", "tokens dropped");
    // The renewal is asked for the one registration, for this sign-in, with this request and
    // response.
    assertThat(asked).hasSize(1);
    assertThat(asked.getFirst().getClientRegistrationId()).isEqualTo("lookahead");
    assertThat(asked.getFirst().getPrincipal()).isSameAs(authentication);
    assertThat(asked.getFirst().getAttributes())
        .containsOnly(
            Map.entry(HttpServletRequest.class.getName(), request),
            Map.entry(HttpServletResponse.class.getName(), response));
    verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
    assertThat(answer.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/bff/logout/complete",
                "providerRevocationConfirmed",
                "true"));
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    assertThat(old.isInvalid()).isTrue();
    upstream.verify();
  }

  @Test
  void cloudSignOutEndsWhenTheDomainSaysTheSignInIsGoneOrCognitoDoesNotConfirmAndWithoutTokens() {
    var handler = handler(CLOUD);
    // The Domain no longer knows the sign-in (401) and there is no refresh token: nothing is asked
    // of Cognito.
    renewalAnswers(tokens("server-only-token", null));
    domainAnswers(HttpStatus.UNAUTHORIZED, "{\"code\":\"AUTHENTICATION_REQUIRED\"}");
    var gone = handler.logout(signOutRequest(), new MockHttpServletResponse(), authentication);
    assertThat(gone.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/bff/logout/complete",
                "providerRevocationConfirmed",
                "false"));
    assertThat(order).containsExactly("tokens renewed", "domain", "tokens dropped");
    upstream.verify();
    upstream.reset();
    order.clear();

    // Cognito does not confirm the revocation: the Domain's sign-out stands, the answer says the
    // provider is unconfirmed.
    renewalAnswers(tokens("server-only-token", "server-refresh"));
    domainAnswers(HttpStatus.OK, "{\"data\":{}}");
    cognitoAnswers(HttpStatus.SERVICE_UNAVAILABLE, "server-refresh");
    var unconfirmed =
        handler.logout(signOutRequest(), new MockHttpServletResponse(), authentication);
    assertThat(unconfirmed.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/bff/logout/complete",
                "providerRevocationConfirmed",
                "false"));
    assertThat(order).containsExactly("tokens renewed", "domain", "cognito", "tokens dropped");
    upstream.verify();
    upstream.reset();
    order.clear();

    // The session holds no provider tokens: nobody is asked, the session still ends.
    renewalAnswers(null);
    var request = signOutRequest();
    var old = (MockHttpSession) request.getSession();
    var none = handler.logout(request, new MockHttpServletResponse(), authentication);
    assertThat(none.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/bff/logout/complete",
                "providerRevocationConfirmed",
                "false"));
    assertThat(order).containsExactly("tokens renewed", "tokens dropped");
    assertThat(old.isInvalid()).isTrue();
    upstream.verify();
  }

  @Test
  void aDomainThatCannotConfirmTheSignOutKeepsThePersonSignedIn() {
    var handler = handler(CLOUD);
    renewalAnswers(tokens("server-only-token", "server-refresh"));
    domainAnswers(HttpStatus.SERVICE_UNAVAILABLE, "{\"code\":\"SERVICE_UNAVAILABLE\"}");
    var request = signOutRequest();
    var response = new MockHttpServletResponse();
    assertThatThrownBy(() -> handler.logout(request, response, authentication))
        .isInstanceOf(RestClientException.class)
        .hasMessage("Domain sign-out could not be confirmed");
    // Cognito is not asked, the tokens stay, the session stays, no answer header is set.
    assertThat(order).containsExactly("tokens renewed", "domain");
    verify(clients, never()).removeAuthorizedClient(any(), any(), any(), any());
    assertThat(((MockHttpSession) request.getSession(false)).isInvalid()).isFalse();
    assertThat(response.getHeader("Cache-Control")).isNull();
    upstream.verify();
  }

  @Test
  void cloudSignOutEndsATestSessionWithoutCallsAndASwitchedOneSignsOutTheKeptStaffSignIn() {
    var handler = handler(CLOUD);
    var testAccount = new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
    // A test session started while signed out: no provider sign-in to end, the DEV gate admission
    // stays.
    var request = signOutRequest();
    var response = new MockHttpServletResponse();
    var old = (MockHttpSession) request.getSession();
    var admission = new DevAccessSession.State("tester", "admission", Instant.now());
    old.setAttribute(DevAccessSession.ATTRIBUTE, admission);
    var ended = handler.logout(request, response, testAccount);
    assertThat(ended.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/sign-in",
                "providerRevocationConfirmed",
                "true"));
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false).getAttribute(DevAccessSession.ATTRIBUTE))
        .isSameAs(admission);
    verifyNoInteractions(manager, clients);
    upstream.verify();

    // Started from a staff sign-in: that sign-in, kept aside in the session, is the one signed out.
    var switched = signOutRequest();
    var switchedResponse = new MockHttpServletResponse();
    switched.getSession().setAttribute(TestSessionState.STAFF_SIGN_IN, authentication);
    var asked = renewalAnswers(tokens("server-only-token", "server-refresh"));
    domainAnswers(HttpStatus.OK, "{\"data\":{}}");
    cognitoAnswers(HttpStatus.OK, "server-refresh");
    var staff = handler.logout(switched, switchedResponse, testAccount);
    assertThat(staff.data())
        .isEqualTo(
            Map.of(
                "logoutUrl",
                "https://learn.example.test/bff/logout/complete",
                "providerRevocationConfirmed",
                "true"));
    assertThat(asked.getFirst().getPrincipal()).isSameAs(authentication);
    verify(clients).removeAuthorizedClient("lookahead", authentication, switched, switchedResponse);
    assertThat(order).containsExactly("tokens renewed", "domain", "cognito", "tokens dropped");
    upstream.verify();
  }

  @Test
  void theSecondStepOfACloudSignOutGoesToCognitosLogoutPageAndDoesNotExistLocally()
      throws Exception {
    var cloud = new MockHttpServletResponse();
    handler(CLOUD).cloudLogoutComplete(cloud);
    assertThat(cloud.getRedirectedUrl())
        .isEqualTo(
            "https://example.auth.us-east-2.amazoncognito.com/logout"
                + "?client_id=syntheticclient123456"
                + "&logout_uri=https%3A%2F%2Flearn.example.test%2Fsign-in");
    assertThat(cloud.getHeader("Cache-Control")).isEqualTo("no-store");

    var local = new MockHttpServletResponse();
    handler(LOCAL).cloudLogoutComplete(local);
    assertThat(local.getStatus()).isEqualTo(404);
    assertThat(local.getRedirectedUrl()).isNull();
    assertThat(local.getHeader("Cache-Control")).isNull();
    verifyNoInteractions(manager, clients);
  }

  @Test
  void leavingDevSignsOutTheStoredSignInEndsTheSessionAndWritesTheExitLineButNoSignOutLine() {
    var handler = spy(handler(CLOUD));
    doReturn(null).when(handler).logout(any(), any(), any());
    var request = new MockHttpServletRequest("POST", "/dev/leave");
    var response = new MockHttpServletResponse();
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);
    var old = (MockHttpSession) request.getSession();
    old.setAttribute("SPRING_SECURITY_CONTEXT", context);
    old.setAttribute(
        DevAccessSession.ATTRIBUTE,
        new DevAccessSession.State("tester", "admission", Instant.now()));
    SecurityContextHolder.getContext().setAuthentication(authentication);
    try (var log = new LogCapture("lookahead.event")) {
      assertThat(handler.leaveDev(request, response)).isTrue();
      verify(handler).logout(request, response, authentication);
      assertThat(log.messages())
          .containsExactly(
              "Exit DEV: the DEV gate closed and the session ended; platform sign-out confirmed:"
                  + " true");
      assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=dev-gate.exit", "event.outcome=success", "signOut.confirmed=true");
    }
    // Leaving DEV closes the gate too: nothing of the old session is carried over.
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false)).isNull();
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void leavingDevEndsTheSessionEvenWhenThePlatformSignOutCannotBeConfirmed() {
    var handler = spy(handler(CLOUD));
    doThrow(
            new IllegalStateException(
                "synthetic upstream unavailable", new IOException("synthetic")))
        .when(handler)
        .logout(any(), any(), any());
    var request = new MockHttpServletRequest("POST", "/dev/leave");
    var response = new MockHttpServletResponse();
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);
    var old = (MockHttpSession) request.getSession();
    old.setAttribute("SPRING_SECURITY_CONTEXT", context);
    try (var log = new LogCapture("lookahead.event")) {
      assertThat(handler.leaveDev(request, response)).isFalse();
      verify(handler).logout(request, response, authentication);
      assertThat(log.messages())
          .containsExactly(
              "Exit DEV: SIGN_OUT_UNCONFIRMED (the platform sign-out could not be confirmed:"
                  + " IllegalStateException < IOException); the session ends anyway",
              "Exit DEV: the DEV gate closed and the session ended; platform sign-out confirmed:"
                  + " false");
      assertThat(log.lines().getFirst().getLevel()).isEqualTo(Level.WARN);
      assertThat(LogCapture.pairs(log.lines().getFirst()))
          .containsExactly(
              "event.action=dev-gate.exit",
              "event.outcome=failure",
              "reason=SIGN_OUT_UNCONFIRMED",
              "exception.types=IllegalStateException < IOException");
      assertThat(log.last().getLevel()).isEqualTo(Level.INFO);
      assertThat(LogCapture.pairs(log.last()))
          .containsExactly(
              "event.action=dev-gate.exit", "event.outcome=success", "signOut.confirmed=false");
      log.assertNothing("synthetic");
    }
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false)).isNull();
  }

  @Test
  void leavingDevFromATestAccountSignsOutTheKeptStaffSignInAndWithNobodySignsNobodyOut() {
    var handler = spy(handler(CLOUD));
    doReturn(null).when(handler).logout(any(), any(), any());
    var request = new MockHttpServletRequest("POST", "/dev/leave");
    var response = new MockHttpServletResponse();
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(
        new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"));
    var session = (MockHttpSession) request.getSession();
    session.setAttribute("SPRING_SECURITY_CONTEXT", context);
    session.setAttribute(TestSessionState.STAFF_SIGN_IN, authentication);
    assertThat(handler.leaveDev(request, response)).isTrue();
    verify(handler).logout(request, response, authentication);
    assertThat(session.isInvalid()).isTrue();

    // No session at all: nobody to sign out, no session is created, the exit is still confirmed.
    var nobody = spy(handler(CLOUD));
    var empty = new MockHttpServletRequest("POST", "/dev/leave");
    assertThat(nobody.leaveDev(empty, new MockHttpServletResponse())).isTrue();
    verify(nobody, never()).logout(any(), any(), any());
    assertThat(empty.getSession(false)).isNull();
    // A session that holds something else under the context name, and no staff sign-in: nobody to
    // sign out either.
    var other = new MockHttpServletRequest("POST", "/dev/leave");
    other.getSession().setAttribute("SPRING_SECURITY_CONTEXT", "not a context");
    assertThat(nobody.leaveDev(other, new MockHttpServletResponse())).isTrue();
    verify(nobody, never()).logout(any(), any(), any());
    verifyNoInteractions(manager, clients);
    upstream.verify();
  }

  /**
   * Not stubbed: leaving DEV runs the same sign-out as the Sign out route, with the stored sign-in,
   * this request and this response.
   */
  @Test
  void leavingDevRunsTheRealCloudSignOutForTheStoredSignIn() {
    var handler = handler(CLOUD);
    var request = new MockHttpServletRequest("POST", "/dev/leave");
    var response = new MockHttpServletResponse();
    var context = SecurityContextHolder.createEmptyContext();
    context.setAuthentication(authentication);
    var old = (MockHttpSession) request.getSession();
    old.setAttribute("SPRING_SECURITY_CONTEXT", context);
    var asked = renewalAnswers(tokens("server-only-token", "server-refresh"));
    domainAnswers(HttpStatus.OK, "{\"data\":{}}");
    cognitoAnswers(HttpStatus.OK, "server-refresh");
    try (var log = new LogCapture("lookahead.event")) {
      assertThat(handler.leaveDev(request, response)).isTrue();
      // One line, the exit line: the "sign-out" line belongs to the Sign out route alone
      // (SignOutLog).
      assertThat(log.lines()).hasSize(1);
      assertThat(LogCapture.pairs(log.last()))
          .contains("event.action=dev-gate.exit")
          .doesNotContain("event.action=sign-out");
    }
    assertThat(order).containsExactly("tokens renewed", "domain", "cognito", "tokens dropped");
    assertThat(asked.getFirst().getPrincipal()).isSameAs(authentication);
    assertThat(asked.getFirst().getAttributes())
        .containsOnly(
            Map.entry(HttpServletRequest.class.getName(), request),
            Map.entry(HttpServletResponse.class.getName(), response));
    verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
    assertThat(old.isInvalid()).isTrue();
    assertThat(request.getSession(false)).isNull();
    upstream.verify();
  }

  @Test
  void theAddressAfterLeavingDevIsTheProvidersLogoutPageReadFromTheSettingsAtEachCall() {
    var environment = devEnvironment();
    var handler = handler(CLOUD, environment);
    assertThat(handler.leaveDevUrl())
        .isEqualTo(
            "https://learner.auth.us-east-2.amazoncognito.com/logout?client_id=learner-client"
                + "&logout_uri=https%3A%2F%2Fdev.example.com%2Fdev%2Fleave%2Fcomplete");
    // The three settings are read from the environment, not from the client details, and at each
    // call.
    environment.setProperty("app.oauth.client-id", "another client");
    assertThat(handler.leaveDevUrl())
        .isEqualTo(
            "https://learner.auth.us-east-2.amazoncognito.com/logout?client_id=another+client"
                + "&logout_uri=https%3A%2F%2Fdev.example.com%2Fdev%2Fleave%2Fcomplete");
    var names = List.of("app.cognito.managed-login", "app.oauth.client-id", "app.oauth.frontend");
    for (String missing : names) {
      var incomplete = new MockEnvironment();
      for (String name : names)
        if (!name.equals(missing)) incomplete.setProperty(name, devEnvironment().getProperty(name));
      assertThatThrownBy(() -> handler(CLOUD, incomplete).leaveDevUrl())
          .as(missing)
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining(missing);
    }
  }
}
