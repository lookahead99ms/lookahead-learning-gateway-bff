package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * DLV-1015: the answer of the DEV session status route for a status and for none (moved here from
 * DevSessionStatusController with its statements).
 */
class DevSessionStatusTest {
  @Test
  void withoutAStatusTheAnswerIs503WithItsCodeAndIsNeverStored() {
    var answer = DevSessionStatus.answer(null);
    assertThat(answer.getStatusCode().value()).isEqualTo(503);
    assertThat(answer.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
    assertThat(answer.getHeaders().headerNames()).containsExactly("Cache-Control");
    assertThat(answer.getBody()).isEqualTo(Map.of("code", "DEV_STATUS_UNAVAILABLE"));
  }

  @Test
  void aStatusIsAnsweredWithItsThreeValuesAndTheDevMarkAndIsNeverStored() {
    var answer = DevSessionStatus.answer(new DevSessionStatus("2031-01-01T00:00:00Z", true, false));
    assertThat(answer.getStatusCode().value()).isEqualTo(200);
    assertThat(answer.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
    assertThat(answer.getHeaders().headerNames()).containsExactly("Cache-Control");
    assertThat(answer.getBody())
        .isEqualTo(
            Map.of(
                "dev",
                true,
                "deadline",
                "2031-01-01T00:00:00Z",
                "warning",
                true,
                "maintenance",
                false));
    // No deadline set: the empty text the store hands over goes out as it is.
    assertThat(DevSessionStatus.answer(new DevSessionStatus("", false, true)).getBody())
        .isEqualTo(Map.of("dev", true, "deadline", "", "warning", false, "maintenance", true));
  }
}
