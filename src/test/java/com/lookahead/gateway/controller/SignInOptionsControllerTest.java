package com.lookahead.gateway.controller;

import static org.assertj.core.api.Assertions.*;

import com.lookahead.gateway.dto.CsrfView;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.*;
import org.springframework.security.web.csrf.DefaultCsrfToken;

/**
 * DLV-1015: the sign-in options and CSRF routes, moved here with their controller from
 * AccountCloudControllerTest.
 */
class SignInOptionsControllerTest {
  /**
   * DLV-969: the options flag follows the Google switch, so our sign-in page shows the button only
   * once Cognito has Google.
   */
  @Test
  void signInOptionsReportTheGoogleSwitch() {
    var on =
        new SignInOptionsController(
            new MockEnvironment().withProperty("app.cognito.google-sign-in", "true"));
    var off = new SignInOptionsController(new MockEnvironment());
    assertThat(on.options(new MockHttpServletResponse()).data())
        .isEqualTo(
            Map.of(
                "registration",
                true,
                "password",
                true,
                "google",
                true,
                "oauth",
                true,
                "managedLogin",
                true));
    assertThat(((Map<?, ?>) off.options(new MockHttpServletResponse()).data()).get("google"))
        .isEqualTo(false);
  }

  @Test
  void bothRoutesForbidStoringTheirAnswer() {
    var controller = new SignInOptionsController(false);
    var options = new MockHttpServletResponse();
    var csrf = new MockHttpServletResponse();
    controller.options(options);
    var view =
        controller.csrf(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "synthetic-token"), csrf);
    assertThat(options.getHeader("Cache-Control")).isEqualTo("no-store");
    assertThat(csrf.getHeader("Cache-Control")).isEqualTo("no-store");
    assertThat(view.data()).isEqualTo(new CsrfView("synthetic-token", "X-CSRF-TOKEN", "_csrf"));
  }
}
