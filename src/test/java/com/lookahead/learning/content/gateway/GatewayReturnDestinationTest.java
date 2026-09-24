package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.assertj.core.api.Assertions.assertThat;

class GatewayReturnDestinationTest {
    @ParameterizedTest
    @ValueSource(strings = {"/", "/#paths", "/?source=login", "/?source=login#paths",
            "/account", "/account?source=login", "/account#password", "/account?source=login#password",
            "/study-plan", "/study-plan/saved?id=example#details", "/learn/java", "/grow#courses",
            "/look-ahead", "/search?q=java%20spring", "/support", "/author/architecture",
            "/delivery-plan", "/delivery-plan?view=roadmap"})
    void preservesRecognizedInternalDestinations(String destination) {
        assertThat(GatewayConfiguration.safeReturn(destination)).isEqualTo(destination);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "https://outside.example/learn", "//outside.example/learn",
            "///outside.example", "javascript:alert(1)", "learn", "/unknown", "/author-other",
            "/\\outside.example", "/learn\\outside", "/learn\r\nLocation: outside",
            "/learn\t", "/learn\u0000", "/learn/%5coutside", "/?next=%0d%0aoutside",
            "/#%00", "/%2foutside.example", "/learn/%", "/learn bad", "/sign-in", "/login", "/oauth2/authorization/lookahead",
            "/sign-up", "/account/other", "/account-other", "/account/", "/delivery-plan/unknown",
            "/learn/../sign-in", "/author/%2e%2e/sign-in", "/learn/./java", "%2Flearn", "%2F"})
    void rejectsUnsafeOrUnrecognizedDestinations(String destination) {
        assertThat(GatewayConfiguration.safeReturn(destination)).isEqualTo("/");
    }

    @Test void missingDestinationDefaultsToHome() {
        assertThat(GatewayConfiguration.safeReturn(null)).isEqualTo("/");
    }

    @Test void successfulLoginUsesHomeWhenSavedDestinationIsMissingOrInvalid() throws Exception {
        var handlers = new GatewaySecurityHandlers(new OAuthSettings("http://127.0.0.1:4301", "fixture", "synthetic",
                "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4301"));
        for (Object saved : new Object[] {null, "//outside.example", 123, "/#paths", "/author/architecture"}) {
            var request = new MockHttpServletRequest();
            if (saved != null) request.getSession().setAttribute("learningReturnTo", saved);
            var response = new MockHttpServletResponse();
            handlers.loginSucceeded(request, response, null);
            String expected = saved instanceof String value ? GatewayConfiguration.safeReturn(value) : "/";
            assertThat(response.getRedirectedUrl()).isEqualTo("http://127.0.0.1:4301" + expected);
            assertThat(request.getSession().getAttribute("learningReturnTo")).isNull();
        }
    }
}
