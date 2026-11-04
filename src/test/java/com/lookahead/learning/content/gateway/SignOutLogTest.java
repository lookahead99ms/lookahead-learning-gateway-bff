package com.lookahead.learning.content.gateway;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

/** DLV-969 (owner, 2026-11-04): Sign out is one line: done, or why not; never who. */
class SignOutLogTest {
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    List<ILoggingEvent> signOut(String method, String path, int status) throws Exception {
        var events = (Logger) LoggerFactory.getLogger("lookahead.event");
        var capture = new ListAppender<ILoggingEvent>(); capture.start(); events.addAppender(capture);
        try {
            new SignOutLog().doFilter(new MockHttpServletRequest(method, path), new MockHttpServletResponse(),
                    (req, res) -> ((HttpServletResponse) res).setStatus(status));
        } finally { events.detachAppender(capture); }
        return capture.list;
    }

    @Test void ownSignInSignOutIsLoggedAndOtherRequestsAreIgnored() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new OAuth2AuthenticationToken(
                new DefaultOAuth2User(Set.of(), Map.of("sub", "person@example.invalid"), "sub"), Set.of(), "lookahead"));
        var done = signOut("POST", SignOutLog.PATH, 200);
        assertThat(done).extracting(ILoggingEvent::getFormattedMessage).containsExactly("Signed out: Domain ended the sign-in and the provider tokens were dropped");
        assertThat(OpsLogTest.pairs(done.getFirst())).contains("event.action=sign-out", "event.outcome=success", "signOut.kind=sign-in");
        var unconfirmed = signOut("POST", SignOutLog.PATH, 503);
        assertThat(unconfirmed.getFirst().getLevel()).isEqualTo(Level.WARN);
        assertThat(unconfirmed.getFirst().getFormattedMessage())
                .isEqualTo("Sign out did not complete: HTTP 503 (Domain could not confirm the sign-out; the person stays signed in and can retry)");
        assertThat(OpsLogTest.pairs(signOut("POST", SignOutLog.PATH, 401).getFirst())).contains("event.outcome=refused", "reason=HTTP_401");
        assertThat(OpsLogTest.pairs(signOut("POST", SignOutLog.PATH, 500).getFirst())).contains("event.outcome=failure", "reason=HTTP_500");
        assertThat(signOut("GET", SignOutLog.PATH, 200)).isEmpty();
        assertThat(signOut("POST", "/bff/api/v1/plans", 200)).isEmpty();
        SecurityContextHolder.clearContext();
        assertThat(signOut("POST", SignOutLog.PATH, 200)).extracting(ILoggingEvent::getFormattedMessage).containsExactly("Sign out with no sign-in in this session");
        for (var line : done) assertThat(line.getFormattedMessage() + OpsLogTest.pairs(line)).doesNotContain("person@example.invalid");
    }
}
