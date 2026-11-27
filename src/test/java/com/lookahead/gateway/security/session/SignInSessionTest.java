package com.lookahead.gateway.security.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/** DLV-1015: the three statements that end a sign-in, written three times in the two account forwarders, in one method. */
class SignInSessionTest {
    private final OAuth2AuthorizedClientRepository clients = mock(OAuth2AuthorizedClientRepository.class);
    private final OAuth2AuthenticationToken authentication =
            new OAuth2AuthenticationToken(new DefaultOAuth2User(Set.of(), Map.of("sub", "account"), "sub"), Set.of(), "lookahead");

    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test void endingDropsTheProviderTokensWhileTheSessionStillExistsThenTheSessionThenTheSecurityContext() {
        var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
        var session = (MockHttpSession) request.getSession();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        // The stored tokens live in the session: they are removed first, while it is still valid and the context still set.
        doAnswer(call -> {
            assertThat(session.isInvalid()).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
            return null;
        }).when(clients).removeAuthorizedClient(any(), any(), any(), any());

        SignInSession.end(clients, authentication, request, response);

        verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
        assertThat(session.isInvalid()).isTrue();
        assertThat(request.getSession(false)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test void aRequestWithoutASessionGetsNoneAndTheContextIsStillCleared() {
        var request = new MockHttpServletRequest(); var response = new MockHttpServletResponse();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        SignInSession.end(clients, authentication, request, response);
        verify(clients).removeAuthorizedClient("lookahead", authentication, request, response);
        assertThat(request.getSession(false)).isNull();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
