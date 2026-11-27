package com.lookahead.gateway.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** The request-input helpers of the password sign-in routes (first tested in PasswordSignInControllerTest). */
class PasswordSignInInputTest {
    @Test void clientAddressUsesTheLastForwardedHop() {
        var request = new MockHttpServletRequest(); request.setRemoteAddr("10.0.0.5");
        assertThat(PasswordSignInInput.address(request)).isEqualTo("10.0.0.5");
        request.addHeader("X-Forwarded-For", "198.51.100.7, 203.0.113.9");
        assertThat(PasswordSignInInput.address(request)).isEqualTo("203.0.113.9");
        var odd = new MockHttpServletRequest(); odd.setRemoteAddr("10.0.0.6"); odd.addHeader("X-Forwarded-For", "x".repeat(80));
        assertThat(PasswordSignInInput.address(odd)).isEqualTo("10.0.0.6");
    }

    static MockHttpServletRequest post(String body) {
        var request = new MockHttpServletRequest("POST", "/bff/api/v1/auth/password/x");
        request.setContent(body.getBytes(StandardCharsets.UTF_8)); request.setContentType("application/json");
        return request;
    }

    /** DLV-1015: the body reading moved here from PasswordSignInController; a JSON object is handed on as it was sent. */
    @Test void readHandsOnTheFieldsOfAJsonObject() {
        var read = PasswordSignInInput.read(post("{\"email\":\"priya@example.invalid\",\"code\":\"123456\"}"));
        assertThat(read.refusal()).isNull();
        assertThat(read.fields().isObject()).isTrue();
        assertThat(PasswordSignInInput.email(read.fields())).isEqualTo("priya@example.invalid");
        assertThat(PasswordSignInInput.code(read.fields())).isEqualTo("123456");
        // Exactly the limit is still read.
        String atLimit = "{\"a\":\"" + "x".repeat(PasswordSignInInput.MAX_BODY - 8) + "\"}";
        assertThat(atLimit.length()).isEqualTo(PasswordSignInInput.MAX_BODY);
        var largest = PasswordSignInInput.read(post(atLimit));
        assertThat(largest.refusal()).isNull();
        assertThat(largest.fields().get("a").asString()).hasSize(PasswordSignInInput.MAX_BODY - 8);
    }

    @Test void readRefusesWhatIsNotAJsonObjectWhatIsTooLargeAndWhatCannotBeRead() throws Exception {
        for (String body : List.of("not json", "[1,2]", "7", "null", "\"text\"", "", "{\"email\":")) {
            var read = PasswordSignInInput.read(post(body));
            assertThat(read.fields()).as(body).isNull();
            assertThat(read.refusal().getStatusCode().value()).as(body).isEqualTo(400);
            assertThat(read.refusal().getBody()).as(body).isEqualTo(Map.of("code", "INVALID_REQUEST"));
            assertThat(read.refusal().getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        }
        var tooLarge = PasswordSignInInput.read(post("{\"a\":\"" + "x".repeat(PasswordSignInInput.MAX_BODY - 7) + "\"}"));
        assertThat(tooLarge.fields()).isNull();
        assertThat(tooLarge.refusal().getStatusCode().value()).isEqualTo(413);
        assertThat(tooLarge.refusal().getBody()).isEqualTo(Map.of("code", "REQUEST_TOO_LARGE"));
        var broken = mock(HttpServletRequest.class);
        when(broken.getInputStream()).thenThrow(new IOException("synthetic read failure"));
        var unreadable = PasswordSignInInput.read(broken);
        assertThat(unreadable.fields()).isNull();
        assertThat(unreadable.refusal().getStatusCode().value()).isEqualTo(400);
        assertThat(unreadable.refusal().getBody()).isEqualTo(Map.of("code", "INVALID_REQUEST"));
    }
}
