package com.lookahead.gateway.util;

import com.lookahead.gateway.dto.ApiResponse;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;

/** The answer builders of the password sign-in routes; the error mapping, the outcome line and the route runner are tested in PasswordSignInHandlerTest. */
class PasswordSignInAnswerTest {
    static Map<?, ?> data(ResponseEntity<?> response) { return (Map<?, ?>) ((ApiResponse<?>) response.getBody()).data(); }

    @Test void aStepIsA200ThatIsNeverStoredAndNamesOnlyWhatItWasGiven() {
        var plain = PasswordSignInAnswer.step("SIGN_IN", null);
        assertThat(plain.getStatusCode().value()).isEqualTo(200);
        assertThat(plain.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(data(plain)).isEqualTo(Map.of("step", "SIGN_IN"));
        assertThat(data(PasswordSignInAnswer.step("CODE_SENT", "a***@example.invalid"))).isEqualTo(Map.of("step", "CODE_SENT", "destination", "a***@example.invalid"));
        var signedIn = PasswordSignInAnswer.step("SIGNED_IN", null, "/learn", true);
        assertThat(signedIn.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(data(signedIn)).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn", "mergeAvailable", true));
        assertThat(List.copyOf(data(signedIn).keySet())).isEqualTo(List.of("step", "next", "mergeAvailable"));
        assertThat(data(PasswordSignInAnswer.step("SIGNED_IN", null, "/learn", false))).isEqualTo(Map.of("step", "SIGNED_IN", "next", "/learn"));
    }

    @Test void aFailureCarriesItsStatusAndCodeAndIsNeverStored() {
        var refused = PasswordSignInAnswer.failure(429, "TOO_MANY_REQUESTS");
        assertThat(refused.getStatusCode().value()).isEqualTo(429);
        assertThat(refused.getHeaders().get("Cache-Control")).isEqualTo(List.of("no-store"));
        assertThat(refused.getBody()).isEqualTo(Map.of("code", "TOO_MANY_REQUESTS"));
    }

    /** What Cognito's delivery details hold is read in PasswordSignInCognitoClient (see its test); here it is the address it named, or none. */
    @Test void theDestinationIsCognitosOwnOrTheMaskedEmail() {
        assertThat(PasswordSignInAnswer.destination("p***@e***", "priya@example.invalid")).isEqualTo("p***@e***");
        assertThat(PasswordSignInAnswer.destination(null, "priya@example.invalid")).isEqualTo("p***@example.invalid");
        assertThat(PasswordSignInAnswer.destination("", "priya@example.invalid")).isEqualTo("p***@example.invalid");
        assertThat(PasswordSignInAnswer.destination("  ", "priya@example.invalid")).isEqualTo("p***@example.invalid");
    }

    @Test void maskedKeepsTheFirstLetterAndTheDomainOnly() {
        assertThat(PasswordSignInAnswer.masked("not-an-email")).isEqualTo("your email");
        assertThat(PasswordSignInAnswer.masked("@example.invalid")).isEqualTo("your email");
        assertThat(PasswordSignInAnswer.masked("priya@example.invalid")).isEqualTo("p***@example.invalid");
    }

}
