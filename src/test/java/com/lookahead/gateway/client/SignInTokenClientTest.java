package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.client.ResourceAccessException;

/**
 * DLV-1015: the token renewal call that five classes wrote out themselves, in one client; the
 * answer and the exceptions are the manager's.
 */
class SignInTokenClientTest {
  private final OAuth2AuthorizedClientManager manager = mock(OAuth2AuthorizedClientManager.class);
  private final SignInTokenClient tokens = new SignInTokenClient(manager);
  private final OAuth2AuthenticationToken authentication =
      new OAuth2AuthenticationToken(
          new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead");

  @Test
  void managerIsAskedForThisSignInsRegistrationWithRequestAndResponseAndItsAnswerReturned() {
    var registration =
        ClientRegistration.withRegistrationId("lookahead")
            .clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize")
            .tokenUri("http://localhost/token")
            .build();
    var client =
        new OAuth2AuthorizedClient(
            registration,
            "account",
            new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER,
                "server-only-token",
                Instant.now(),
                Instant.now().plusSeconds(300)));
    when(manager.authorize(any())).thenReturn(client);
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();

    assertThat(tokens.authorize(authentication, request, response)).isSameAs(client);

    var asked = ArgumentCaptor.forClass(OAuth2AuthorizeRequest.class);
    verify(manager).authorize(asked.capture());
    assertThat(asked.getValue().getClientRegistrationId()).isEqualTo("lookahead");
    assertThat(asked.getValue().getPrincipal()).isSameAs(authentication);
    assertThat(asked.getValue().getAuthorizedClient()).isNull();
    // Exactly the two attributes Spring Security's manager reads, under the names it reads them by,
    // in this order.
    assertThat(asked.getValue().getAttributes().keySet())
        .containsExactly(HttpServletRequest.class.getName(), HttpServletResponse.class.getName());
    assertThat(asked.getValue().getAttributes().get(HttpServletRequest.class.getName()))
        .isSameAs(request);
    assertThat(asked.getValue().getAttributes().get(HttpServletResponse.class.getName()))
        .isSameAs(response);
    // No session is created and nothing is written to the response by this class.
    assertThat(request.getSession(false)).isNull();
    assertThat(response.getHeaderNames()).isEmpty();
  }

  @Test
  void aSessionWithoutProviderTokensIsNullAndEveryExceptionOfTheManagerPassesThroughUnchanged() {
    var request = new MockHttpServletRequest();
    var response = new MockHttpServletResponse();
    when(manager.authorize(any())).thenReturn(null);
    assertThat(tokens.authorize(authentication, request, response)).isNull();

    var refused = new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));
    doThrow(refused).when(manager).authorize(any());
    assertThatThrownBy(() -> tokens.authorize(authentication, request, response)).isSameAs(refused);

    var down = new ResourceAccessException("synthetic");
    doThrow(down).when(manager).authorize(any());
    assertThatThrownBy(() -> tokens.authorize(authentication, request, response)).isSameAs(down);
  }

  @Test
  void aMissingSignInIsRefusedBeforeTheManagerIsAskedAsTheCallSitesDidThemselves() {
    // Spring Security's request builder refuses a null principal; the manager is not asked.
    assertThatThrownBy(() ->
            tokens.authorize(null, new MockHttpServletRequest(), new MockHttpServletResponse()))
        .isInstanceOf(IllegalArgumentException.class);
    verifyNoInteractions(manager);
  }
}
