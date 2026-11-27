package com.lookahead.gateway.util;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;

/** DLV-1015: the two answer builders of the test-session routes (moved from TestSessionDomainClient, unchanged). */
class TestSessionAnswerTest {
    @Test void aJsonAnswerCarriesItsStatusAndBodyAndIsNeverStored() {
        byte[] body = "{\"data\":[]}".getBytes(StandardCharsets.UTF_8);
        var answer = TestSessionAnswer.json(200, body);
        assertThat(answer.getStatusCode().value()).isEqualTo(200);
        assertThat(answer.getBody()).isSameAs(body);
        assertThat(answer.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(answer.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        var unavailable = TestSessionAnswer.json(503, new byte[0]);
        assertThat(unavailable.getStatusCode().value()).isEqualTo(503);
        assertThat(unavailable.getBody()).isEmpty();
    }

    @Test void aFailureIsAJsonAnswerWithItsCodeAndMessage() {
        var refused = TestSessionAnswer.failure(409, "NO_TEST_SESSION", "No test account is in use.");
        assertThat(refused.getStatusCode().value()).isEqualTo(409);
        assertThat(new String(refused.getBody(), StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"NO_TEST_SESSION\",\"message\":\"No test account is in use.\"}");
        assertThat(refused.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(refused.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
    }
}
