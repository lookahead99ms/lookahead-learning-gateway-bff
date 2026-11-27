package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.controller.DevWebController;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/** The forwarder to the static Web: which paths it may serve, which Web upstream it accepts, and the line it writes when it refuses Web's answer. */
class DevWebProxyTest {
    @Test void staticProxyRejectsReservedAndAmbiguousTargets() {
        for(String path:new String[]{"//evil", "/bff/private", "/content/private", "/%2e%2e", "/x/../y", "/dev/access", "/.git/config", "/key.pem"})
            assertFalse(DevWebProxy.safePath(path),path);
        assertTrue(DevWebProxy.safePath("/learn")); assertTrue(DevWebProxy.safePath("/main-abcdef123.js"));
    }

    @Nested class WebUpstream {
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    /** DLV-1015: the path check and its 404, moved here from DevWebController with their statements. */
    @Test void forwardTakesThePathFromTheRequestAndAnswers404ForAPathItMayNotServeWithoutAskingTheWeb() {
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn")).andRespond(withSuccess("<html>shell</html>",MediaType.TEXT_HTML));
        var proxy=new DevWebProxy(builder.build(),DevServiceOrigins.from(upstreams()));
        var request=new MockHttpServletRequest("GET","/learn");request.setQueryString("token=private");
        assertThat(proxy.forward(request).getStatusCode().value()).isEqualTo(200);
        server.verify();
        Assertions.assertEquals(404,proxy.forward(new MockHttpServletRequest("GET","/content/private")).getStatusCode().value());
        // Every path the rule refuses is a bare 404: no body, no header, and the Web is never asked.
        for(String path:new String[]{"//evil", "/bff/private", "/content/private", "/%2e%2e", "/x/../y", "/dev/access", "/.git/config", "/key.pem", "/a;b", "/a\\b"}){
            var refused=proxy.forward(new MockHttpServletRequest("HEAD",path));
            assertThat(refused.getStatusCode().value()).as(path).isEqualTo(404);
            assertThat(refused.getBody()).isNull();
            assertThat(refused.getHeaders().isEmpty()).isTrue();
        }
        server.verify();
    }
    MockEnvironment upstreams(){return new MockEnvironment().withProperty("app.oauth.domain-api-upstream","https://domain.lookahead-dev.internal:8443")
        .withProperty("app.gateway.web-upstream","https://web.lookahead-dev.internal:8443");}
    @Test void webProxyRefusesAnyWebUpstreamOtherThanTheStableName() {
        for(String rejected:List.of("https://web.attacker.test:8443","https://web.lookahead-dev.internal:8081","http://web.lookahead-dev.internal:8443"))
            assertThrows(IllegalStateException.class,()->new DevWebProxy(RestClient.builder().build(),DevServiceOrigins.from(upstreams().withProperty("app.gateway.web-upstream",rejected))),rejected);
        assertThrows(IllegalStateException.class,()->new DevWebProxy(RestClient.builder().build(),DevServiceOrigins.from(new MockEnvironment())));
        // DLV-1015: the route receives the forwarder ready-made, so a wrong Web upstream is refused while the forwarder is built, before the route is.
        assertThrows(IllegalStateException.class,()->new DevWebController(new DevWebProxy(RestClient.builder().build(),DevServiceOrigins.from(new MockEnvironment()))));
        assertThrows(IllegalStateException.class,()->new DevWebController(new DevWebProxy(RestClient.builder().build(),DevServiceOrigins.from(upstreams().withProperty("app.gateway.web-upstream","https://web.attacker.test:8443")))));
    }
    }

    /**
     * DLV-969 (owner, 2026-11-04): each fallback that used to answer 502 or 503 without a word now writes one WARN line with
     * what was being done and why: a stable reason code, the upstream status and exception types. Never a body or a token.
     */
    @Nested class FallbackReason {
    static final String SECRET = "synthetic-body-secret";
    static final String TOKEN = "synthetic-server-token";
    final LogCapture log = new LogCapture("lookahead.event");

    @AfterEach void close() { log.close(); }

    void reason(String action, String reason) {
        assertThat(log.lines()).isNotEmpty();
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.action=" + action, "reason=" + reason);
        log.assertNothing(SECRET, TOKEN);
    }

    @Test void theWebProxySaysWhichRuleRefusedWebsAnswer() {
        var environment = new MockEnvironment().withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443")
                .withProperty("app.gateway.web-upstream", "https://web.lookahead-dev.internal:8443");
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", "https://elsewhere.example/" + SECRET));
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
                .andRespond(withSuccess(new byte[16 * 1024 * 1024 + 1], MediaType.TEXT_HTML));
        var proxy = new DevWebController(new DevWebProxy(builder.build(), DevServiceOrigins.from(environment)));
        assertThat(proxy.get(new MockHttpServletRequest("GET", "/learn")).getStatusCode().value()).isEqualTo(502);
        reason("web.proxy", "WEB_REDIRECT_REFUSED");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Web answer for GET /learn refused with 502: WEB_REDIRECT_REFUSED (Web answered a redirect (HTTP 302), "
                + "which the Gateway never follows or relays)");
        assertThat(proxy.get(new MockHttpServletRequest("GET", "/learn")).getStatusCode().value()).isEqualTo(502);
        reason("web.proxy", "WEB_ANSWER_TOO_LARGE");
        assertThat(LogCapture.pairs(log.last())).contains("upstream.status=200", "url.path=/learn");
        server.verify();
    }
    }
}
