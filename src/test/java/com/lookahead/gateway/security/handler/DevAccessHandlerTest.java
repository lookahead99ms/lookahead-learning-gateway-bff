package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.lookahead.gateway.security.oauth.SignInProvider;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.DefaultCsrfToken;

/**
 * DLV-1015: what the DEV gate's own routes answer, driven directly on the handler (the statements
 * moved here from DevAccessController). The same answers through the route methods are in
 * DevAccessControllerTest; the sign-out behind leaving DEV is in SignOutHandlerTest, and the page
 * template with its policy hash is DevAccessPage's.
 */
class DevAccessHandlerTest {
  final SignOutHandler signOut = mock(SignOutHandler.class);

  @Test
  void thePageIsNeverStoredCarriesItsOwnPolicyAndShowsGoogleOnlyWhenTheHandlerWasBuiltWithIt() {
    var off = new DevAccessHandler(false, signOut).access(null, null);
    var on = new DevAccessHandler(true, signOut).access(null, null);
    for (var reply : List.of(off, on)) {
      assertThat(reply.getStatusCode().value()).isEqualTo(200);
      assertThat(reply.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
      assertThat(reply.getHeaders().get("Content-Security-Policy"))
          .isEqualTo(List.of(DevAccessPage.load(DevAccessPage.RESOURCE).policy));
      assertThat(reply.getHeaders().headerNames())
          .containsExactlyInAnyOrder("Cache-Control", "Content-Security-Policy");
      assertThat(reply.getBody())
          .startsWith("<!doctype html>")
          .doesNotContain("<!--")
          .doesNotContain("class=\"notice\"");
    }
    assertThat(off.getBody())
        .doesNotContain("Continue with Google")
        .doesNotContain("provider=google");
    assertThat(on.getBody())
        .contains("Continue with Google")
        .contains("href=\"/bff/login?provider=google&amp;returnTo=%2F\"");
    // The page is exactly what the template renders for that switch and that notice.
    var page = DevAccessPage.load(DevAccessPage.RESOURCE);
    assertThat(off.getBody()).isEqualTo(page.render(false, DevAccessPage.Notice.NONE));
    assertThat(on.getBody()).isEqualTo(page.render(true, DevAccessPage.Notice.NONE));
    verifyNoInteractions(signOut);
  }

  /**
   * The switch is a start-up setting: the configuration reads it once, and a later change of the
   * environment does not reach a built handler.
   */
  @Test
  void theGoogleSwitchIsWhatItWasWhenTheHandlerWasBuilt() {
    var environment = new MockEnvironment().withProperty("app.cognito.google-sign-in", "true");
    var handler = new DevAccessHandler(SignInProvider.googleEnabled(environment), signOut);
    assertThat(handler.access(null, null).getBody()).contains("Continue with Google");
    environment.setProperty("app.cognito.google-sign-in", "false");
    assertThat(handler.access(null, null).getBody()).contains("Continue with Google");
    assertThat(
            new DevAccessHandler(SignInProvider.googleEnabled(new MockEnvironment()), signOut)
                .access(null, null)
                .getBody())
        .doesNotContain("Continue with Google");
  }

  @Test
  void theNoticeIsChosenFromTheTwoParametersAndIsAlwaysFixedText() {
    var handler = new DevAccessHandler(false, signOut);
    var page = DevAccessPage.load(DevAccessPage.RESOURCE);
    assertThat(handler.access("pending", null).getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.PENDING))
        .contains(
            "<p class=\"notice\" role=\"status\">Your sign-in worked. The owner has to approve your"
                + " access before DEV opens.");
    assertThat(handler.access("pending", "signin").getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.PENDING));
    assertThat(handler.access(null, "<b>anything</b>").getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.FAILED))
        .contains("That sign-in did not complete. Try again.")
        .doesNotContain("<b>anything");
    assertThat(handler.access("other", "").getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.FAILED));
    assertThat(handler.access("other", null).getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.NONE));
    assertThat(handler.access("PENDING", null).getBody())
        .isEqualTo(page.render(false, DevAccessPage.Notice.NONE));
  }

  @Test
  void csrfAnswersTheHeaderNameAndTheTokenAndIsNeverStored() {
    var reply =
        new DevAccessHandler(false, signOut)
            .csrf(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "synthetic-token"));
    assertThat(reply.getStatusCode().value()).isEqualTo(200);
    assertThat(reply.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
    assertThat(reply.getBody())
        .isEqualTo(Map.of("headerName", "X-CSRF-TOKEN", "token", "synthetic-token"));
    verifyNoInteractions(signOut);
  }

  @Test
  void leaveSignsOutFirstThenAnswersWhereToGoAndWhetherTheSignOutWasConfirmed() {
    var handler = new DevAccessHandler(true, signOut);
    for (boolean confirmed : new boolean[] {true, false}) {
      Mockito.reset(signOut);
      var request = new MockHttpServletRequest("POST", "/dev/leave");
      var response = new MockHttpServletResponse();
      doReturn(confirmed).when(signOut).leaveDev(request, response);
      doReturn("https://provider.example/logout?logout_uri=x").when(signOut).leaveDevUrl();
      var reply = handler.leave(request, response);
      assertThat(reply.getStatusCode().value()).isEqualTo(200);
      assertThat(reply.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
      assertThat(reply.getBody())
          .isEqualTo(
              Map.of(
                  "logoutUrl",
                  "https://provider.example/logout?logout_uri=x",
                  "learnerSignOutConfirmed",
                  Boolean.toString(confirmed),
                  "providerRevocationConfirmed",
                  "false"));
      // The sign-out comes first; the address is asked for after it, once each.
      var order = inOrder(signOut);
      order.verify(signOut).leaveDev(request, response);
      order.verify(signOut).leaveDevUrl();
      verifyNoMoreInteractions(signOut);
      assertThat(response.getHeaderNames()).isEmpty();
    }
  }

  @Test
  void completeSendsTheBrowserBackToTheGatePageUnstored() throws Exception {
    var response = new MockHttpServletResponse();
    new DevAccessHandler(false, signOut).complete(response);
    assertThat(response.getRedirectedUrl()).isEqualTo("/dev/access");
    assertThat(response.getStatus()).isEqualTo(302);
    assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
    verifyNoInteractions(signOut);
  }
}
