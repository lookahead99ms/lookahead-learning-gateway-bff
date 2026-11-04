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
            "/blaze", "/blaze/system-design", "/blaze/system-design/module/caching#notes",
            "/look-ahead", "/look-ahead/system-design", "/search?q=java%20spring", "/support", "/author/architecture",
            "/pricing", "/delivery-plan", "/delivery-plan?view=roadmap", "/admin", "/admin/reviews", "/admin/docs#start-here"})
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
            "/learn/../sign-in", "/author/%2e%2e/sign-in", "/admin/../sign-in", "/administrator", "/admin-other",
            "/blazer", "/blaze-other", "/blaze/../sign-in", "/look-aheadx","/learn/./java", "%2Flearn", "%2F"})
    void rejectsUnsafeOrUnrecognizedDestinations(String destination) {
        assertThat(GatewayConfiguration.safeReturn(destination)).isEqualTo("/");
    }

    /** DLV-969 S36: the merge page with its email token and/or the offer flag; T is 43 url-safe characters. */
    static final String T = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_Z";

    @ParameterizedTest
    @ValueSource(strings = {"/account/merge", "/account/merge?offer=1", "/account/merge?token=" + T,
            "/account/merge?token=" + T + "&offer=1", "/account/merge?offer=1&token=" + T})
    void preservesTheMergePageWithItsTokenOrOffer(String destination) {
        assertThat(T).hasSize(43);
        assertThat(GatewayConfiguration.safeReturn(destination)).isEqualTo(destination);
    }

    @ParameterizedTest
    @ValueSource(strings = {"/account/merge?", "/account/merge?offer=0", "/account/merge?offer=2", "/account/merge?offer=1&offer=1",
            "/account/merge?offer", "/account/merge?offer=1&", "/account/merge?&offer=1", "/account/merge?OFFER=1",
            "/account/merge?token=", "/account/merge?token=short", "/account/merge?token=" + T + "x", "/account/merge?token=" + T + "&token=" + T,
            "/account/merge?token=abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_%5A", "/account/merge?token=abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123-_.",
            "/account/merge?token=" + T + "%26offer=1", "/account/merge?TOKEN=" + T, "/account/merge?token=" + T + "&next=/admin",
            "/account/merge?returnTo=//outside.example", "/account/merge?offer=1#x", "/account/merge#offer=1", "/account/merge#", "/account/merge?#", "/account/merge?offer=1#", "/account/merge?token=" + T + "#t",
            "/account/merge/", "/account/merge/x?offer=1", "/account/mergex?offer=1", "/account/merge;x?offer=1",
            "/account%2Fmerge?offer=1", "/account%2fmerge", "/account/merg%65?offer=1", "/account/merge%3Foffer=1",
            "//account/merge?offer=1", "///account/merge?offer=1", "//outside.example/account/merge?offer=1",
            "https://outside.example/account/merge?offer=1", "/account/../account/merge?offer=1", "/account/./merge?offer=1",
            "/account\\merge?offer=1", "/account/merge?offer=1\r\nLocation: outside", "/account/merge?offer=1\t", "account/merge?offer=1"})
    void rejectsAnyOtherMergeDestination(String destination) {
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
