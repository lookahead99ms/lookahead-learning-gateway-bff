package com.lookahead.gateway.dto;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.security.web.csrf.DefaultCsrfToken;

/**
 * DLV-1015: the body both CSRF routes built with the same expression (SignInController and
 * SignInOptionsController).
 */
class CsrfViewTest {
  @Test
  void theViewCarriesTheTokenItsHeaderNameAndItsParameterName() {
    var view = CsrfView.from(new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "synthetic-token"));
    assertThat(view).isEqualTo(new CsrfView("synthetic-token", "X-CSRF-TOKEN", "_csrf"));
  }
}
