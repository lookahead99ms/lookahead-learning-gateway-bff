package com.lookahead.learning.content.gateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.LogCapture;
import com.lookahead.learning.content.oauth.OAuthSettings;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * DLV-969 (owner, 2026-11-04): each fallback that used to answer 502 or 503 without a word now writes one WARN line with
 * what was being done and why: a stable reason code, the upstream status and exception types. Never a body or a token.
 */
class FallbackReasonLogTest {
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

    @Test void anUnreadableDomainAnswerIsNotReportedAsDomainBeingDown() {
        var settings = OAuthSettings.from(new GatewayDeploymentTest().production());
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(settings.domainApiUpstream() + "/internal/v1/cloud-sign-ins/admit"))
                .andRespond(withSuccess("<html>" + SECRET + "</html>", MediaType.TEXT_HTML));
        server.expect(requestTo(settings.domainApiUpstream() + "/internal/v1/cloud-sign-ins/admit"))
                .andRespond(withStatus(HttpStatus.BAD_GATEWAY).body("x".repeat(16385)));
        var sessions = new CloudGatewaySessions(settings, builder.build());
        assertThatThrownBy(() -> sessions.call("admit", TOKEN, new MockHttpServletRequest(), Map.of())).isInstanceOf(RestClientException.class);
        reason("cloud-session.admit", "ANSWER_NOT_JSON");
        assertThat(log.last().getFormattedMessage()).startsWith("Domain's answer to cloud sign-in admit (HTTP 200) was unreadable: not JSON (");
        assertThat(LogCapture.pairs(log.last())).contains("upstream.service=domain", "upstream.status=200");
        assertThatThrownBy(() -> sessions.call("admit", TOKEN, new MockHttpServletRequest(), Map.of())).isInstanceOf(RestClientException.class);
        reason("cloud-session.admit", "ANSWER_TOO_LARGE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Domain's answer to cloud sign-in admit (HTTP 502) was unreadable: larger than 16 KB");
        server.verify();
    }

    @Test void theWebProxySaysWhichRuleRefusedWebsAnswer() {
        var environment = new MockEnvironment().withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443")
                .withProperty("app.gateway.web-upstream", "https://web.lookahead-dev.internal:8443");
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", "https://elsewhere.example/" + SECRET));
        server.expect(requestTo("https://web.lookahead-dev.internal:8443/learn"))
                .andRespond(withSuccess(new byte[16 * 1024 * 1024 + 1], MediaType.TEXT_HTML));
        var proxy = new DevWebProxy(builder.build(), environment);
        assertThat(proxy.get(new MockHttpServletRequest("GET", "/learn")).getStatusCode().value()).isEqualTo(502);
        reason("web.proxy", "WEB_REDIRECT_REFUSED");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Web answer for GET /learn refused with 502: Web answered a redirect (HTTP 302), "
                + "which the Gateway never follows or relays");
        assertThat(proxy.get(new MockHttpServletRequest("GET", "/learn")).getStatusCode().value()).isEqualTo(502);
        reason("web.proxy", "WEB_ANSWER_TOO_LARGE");
        assertThat(LogCapture.pairs(log.last())).contains("upstream.status=200", "url.path=/learn");
        server.verify();
    }

    @Test void identityAnswersTooLargeOrNotJsonAreNamed() throws Exception {
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        var settings = new OAuthSettings("http://127.0.0.1:4350", "lookahead-test", "synthetic-client-secret-only-for-testing",
                "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
        var identity = new IdentityProxyController(settings, builder.build(), "IDENTITY_TEST");
        var account = new AccountProxyController(identity, new MockEnvironment().withProperty("server.servlet.session.cookie.secure", "false"));
        server.expect(requestTo("http://identity:8080/api/v1/account/profile")).andRespond(withSuccess("x".repeat(AccountProxyController.MAX_ACCOUNT_BYTES + 1), MediaType.TEXT_PLAIN));
        server.expect(requestTo("http://identity:8080/api/v1/account/sign-ins/label")).andRespond(withSuccess(SECRET + " is not json", MediaType.APPLICATION_JSON));
        assertThat(account.profile(new MockHttpServletRequest("GET", "/api/v1/account/profile")).getStatusCode().value()).isEqualTo(503);
        reason("identity.proxy", "IDENTITY_ANSWER_TOO_LARGE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Identity answer for GET /api/v1/account/profile refused with 502: larger than 8192 bytes");
        assertThat(account.updateSignIns(new MockHttpServletRequest("POST", "/api/v1/account/sign-ins/label")).getStatusCode().value()).isEqualTo(503);
        reason("account.identity", "IDENTITY_ANSWER_NOT_JSON");
        assertThat(log.last().getFormattedMessage()).startsWith("Identity's answer to POST /api/v1/account/sign-ins/label was not readable JSON (");
        server.verify();
    }

    @Test void authorPreviewFallbacksSayWhy() {
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        String access = "http://domain-api:8080/api/v1/author/previews/access", source = "http://127.0.0.1:4315/preview-directory/manifest.json";
        String path = AuthorPreviewPath.PREFIX + "preview-directory/manifest.json";
        var proxy = new AuthorPreviewProxy(new AuthorPreviewSettings(URI.create("http://127.0.0.1:4315"), AuthorPreviewSettingsTest.SOURCE_SECRET),
                AuthorPreviewSettingsTest.OAUTH, builder.build());
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.NO_CONTENT));
        server.expect(requestTo(source)).andRespond(withStatus(HttpStatus.SERVICE_UNAVAILABLE));
        server.expect(requestTo(access)).andRespond(withStatus(HttpStatus.NO_CONTENT));
        server.expect(requestTo(source)).andRespond(withSuccess("x", MediaType.APPLICATION_JSON).header(HttpHeaders.CONTENT_LENGTH, String.valueOf(AuthorPreviewProxy.MAX_BYTES + 1)));
        server.expect(requestTo(access)).andRespond(withException(new java.io.IOException(SECRET)));
        assertThat(proxy.fetch("GET", path, null, TOKEN).getStatusCode().value()).isEqualTo(403);
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.outcome=refused", "reason=PREVIEW_ACCESS_REFUSED");
        assertThat(proxy.fetch("GET", path, null, TOKEN).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_ACCESS_CHECK_FAILED");
        assertThat(proxy.fetch("GET", path, null, TOKEN).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_SERVER_HTTP_503");
        assertThat(proxy.fetch("GET", path, null, TOKEN).getStatusCode().value()).isEqualTo(502);
        reason("author-preview.fetch", "PREVIEW_TOO_LARGE");
        assertThat(proxy.fetch("GET", path, null, TOKEN).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "PREVIEW_UNAVAILABLE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Author preview answered 503: Domain or the local preview server did not answer "
                + "(ResourceAccessException < IOException) (PREVIEW_UNAVAILABLE)");
        server.verify();

        var principal = new OAuth2AuthenticationToken(new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "s"), "sub"),
                List.of(new SimpleGrantedAuthority("ROLE_USER")), "lookahead");
        OAuth2AuthorizedClientManager expired = request -> { throw new OAuth2AuthorizationException(new OAuth2Error("invalid_grant", SECRET, null)); };
        var request = new MockHttpServletRequest("GET", path);
        assertThat(new AuthorPreviewController(expired, proxy).preview(request, new MockHttpServletResponse(), principal).getStatusCode().value()).isEqualTo(401);
        assertThat(LogCapture.pairs(log.last())).contains("reason=SESSION_EXPIRED");
        assertThat(log.last().getFormattedMessage()).contains("(invalid_grant)");
        OAuth2AuthorizedClientManager down = request2 -> { throw new ResourceAccessException(SECRET); };
        assertThat(new AuthorPreviewController(down, proxy).preview(request, new MockHttpServletResponse(), principal).getStatusCode().value()).isEqualTo(503);
        reason("author-preview.fetch", "TOKEN_REFRESH_UNAVAILABLE");
        // A request that never reaches an upstream (malformed path, missing token) stays quiet: the request line says it.
        log.clear();
        assertThat(proxy.fetch("GET", "/elsewhere", null, TOKEN).getStatusCode().value()).isEqualTo(400);
        assertThat(log.lines()).isEmpty();
    }

    @Test void aMalformedDevDeadlineIsNamedAndLoggedAtMostOnceAMinute() {
        var client = mock(software.amazon.awssdk.services.dynamodb.DynamoDbClient.class);
        var bad = software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s("tomorrow-" + SECRET).build();
        var good = software.amazon.awssdk.services.dynamodb.model.AttributeValue.builder().s(java.time.Instant.now().plusSeconds(3600).toString()).build();
        var answers = new java.util.ArrayDeque<>(List.of(bad, bad, good, bad));
        org.mockito.Mockito.when(client.getItem(any(java.util.function.Consumer.class))).thenAnswer(call ->
                software.amazon.awssdk.services.dynamodb.model.GetItemResponse.builder().item(Map.of("deadline", answers.poll())).build());
        var status = new DevSessionStatus(client, "state");
        assertThat(status.status().getStatusCode().value()).isEqualTo(503);
        reason("dev-session.status", "DEV_STATUS_INVALID");
        assertThat(status.status().getStatusCode().value()).isEqualTo(503);  // same problem within the minute: quiet
        assertThat(log.lines()).hasSize(1);
        assertThat(status.status().getStatusCode().value()).isEqualTo(200);  // recovered
        assertThat(status.status().getBody()).containsEntry("code", "DEV_STATUS_UNAVAILABLE");  // fails again: logged at once
        assertThat(log.lines()).hasSize(2);
        assertThat(log.last().getFormattedMessage()).contains("deadline attribute is not an ISO-8601 instant");
    }

    @Test void repeatsAreDueOnChangeAndOnceAMinute() {
        var clock = new AtomicLong();
        var repeats = new OpsLog.Repeats(Duration.ofMinutes(1), clock::get);
        assertThat(repeats.due("A")).isTrue();
        clock.addAndGet(Duration.ofSeconds(59).toNanos());
        assertThat(repeats.due("A")).isFalse();
        assertThat(repeats.due("B")).isTrue();
        clock.addAndGet(Duration.ofSeconds(60).toNanos());
        assertThat(repeats.due("B")).isTrue();
        repeats.clear();
        assertThat(repeats.due("B")).isTrue();
        assertThat(new OpsLog.Repeats(Duration.ofSeconds(1)).due("x")).isTrue();
    }
}
