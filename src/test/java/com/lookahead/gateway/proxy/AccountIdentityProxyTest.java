package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.controller.AccountIdentityController;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.match.MockRestRequestMatchers;
import org.springframework.web.client.RestClient;

/**
 * DLV-1015: the account forwarder driven directly (moved here from AccountIdentityController, statements unchanged); the
 * routes drive it in AccountIdentityControllerTest and IdentityProxyControllerIntegrationTest.
 */
class AccountIdentityProxyTest {
    @Nested class Forwarding {
    private static final String PASSWORD = "http://identity:8080/api/v1/account/password";
    private static final String REVOKE = "http://identity:8080/api/v1/account/sign-ins/revoke";
    private final RestClient.Builder http = RestClient.builder();
    private final MockRestServiceServer upstream = MockRestServiceServer.bindTo(http).build();
    private final OAuthClientDetails oauth = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-test",
            "synthetic-client-secret-only-for-testing", "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
    private final IdentityProxy identity = new IdentityProxy(oauth, http.build(), "IDENTITY_TEST", "LOOKAHEAD_SIGNIN_BINDING", "LOOKAHEAD_SIGNIN_CHALLENGE", "LOOKAHEAD_GATEWAY");
    private final AccountIdentityProxy proxy = new AccountIdentityProxy(identity, new MockEnvironment());

    @AfterEach void clearContext() { SecurityContextHolder.clearContext(); upstream.verify(); }

    private static MockHttpServletRequest signedIn(String path, MockHttpSession session) {
        var request = new MockHttpServletRequest("POST", path);
        request.setSession(session);
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("user", "unused"));
        return request;
    }

    @Test void forwardKeepsIdentitysOwnAnswersAndReplacesEveryServerErrorWithOnePlain503() throws Exception {
        upstream.expect(requestTo("http://identity:8080/api/v1/account/profile"))
                .andRespond(withStatus(HttpStatus.CONFLICT).contentType(MediaType.APPLICATION_JSON).body("{\"code\":\"EXPECTED_ERROR\"}"));
        var kept = proxy.forward(new MockHttpServletRequest("GET", "/api/v1/account/profile"));
        assertThat(kept.getStatusCode().value()).isEqualTo(409);
        assertThat(new String(kept.getBody(), StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"EXPECTED_ERROR\"}");
        assertThat(kept.getHeaders().getCacheControl()).isEqualTo("no-store");
        for (int status : new int[]{500, 502, 503, 504}) {
            upstream.verify(); upstream.reset();
            upstream.expect(requestTo("http://identity:8080/api/v1/account/profile"))
                    .andRespond(withStatus(HttpStatus.valueOf(status)).body("database secret details"));
            var replaced = proxy.forward(new MockHttpServletRequest("GET", "/api/v1/account/profile"));
            assertThat(replaced.getStatusCode().value()).isEqualTo(503);
            assertThat(replaced.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            assertThat(replaced.getHeaders().getFirst(HttpHeaders.CONTENT_TYPE)).isEqualTo("application/json");
            assertThat(new String(replaced.getBody(), StandardCharsets.UTF_8)).isEqualTo(
                    "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"The account service is temporarily unavailable. Retry shortly.\"}");
        }
    }

    /** DLV-1015: the method guard of the profile route, moved here from AccountIdentityController with its statements. */
    @Test void profileLetsOnlyGetAndPostReachIdentityAndAnswersAnyOtherMethodWith405() throws Exception {
        // Spring maps HEAD implicitly to GET, so the route is reached with HEAD too; nothing but the published methods goes on.
        for (String method : new String[]{"HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE"}) {
            var refused = proxy.profile(new MockHttpServletRequest(method, "/api/v1/account/profile"));
            assertThat(refused.getStatusCode().value()).as(method).isEqualTo(405);
            assertThat(refused.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            assertThat(refused.getHeaders().headerNames()).containsExactly(HttpHeaders.CACHE_CONTROL);
            assertThat(refused.getBody()).isNull();
        }
        upstream.verify();
        for (String method : new String[]{"GET", "POST"}) {
            upstream.reset();
            upstream.expect(requestTo("http://identity:8080/api/v1/account/profile")).andExpect(MockRestRequestMatchers.method(HttpMethod.valueOf(method)))
                    .andRespond(withSuccess("{\"data\":{}}", MediaType.APPLICATION_JSON));
            var forwarded = proxy.profile(new MockHttpServletRequest(method, "/api/v1/account/profile"));
            assertThat(forwarded.getStatusCode().value()).as(method).isEqualTo(200);
            assertThat(new String(forwarded.getBody(), StandardCharsets.UTF_8)).isEqualTo("{\"data\":{}}");
            upstream.verify();
        }
        // What forward does to Identity's answer still applies behind the guard.
        upstream.reset();
        upstream.expect(requestTo("http://identity:8080/api/v1/account/profile")).andRespond(withStatus(HttpStatus.BAD_GATEWAY).body("database secret details"));
        assertThat(proxy.profile(new MockHttpServletRequest("GET", "/api/v1/account/profile")).getStatusCode().value()).isEqualTo(503);
    }

    /** DLV-1015: the method guard of the two read-only routes, moved here from AccountIdentityController with its statements. */
    @Test void signInsLetsOnlyGetReachIdentityAndAnswersAnyOtherMethodWith405() throws Exception {
        for (String path : new String[]{"/api/v1/account/sign-ins", "/api/v1/auth/sign-in-challenge"}) {
            for (String method : new String[]{"HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}) {
                var refused = proxy.signIns(new MockHttpServletRequest(method, path));
                assertThat(refused.getStatusCode().value()).as(method + " " + path).isEqualTo(405);
                assertThat(refused.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
                assertThat(refused.getHeaders().headerNames()).containsExactly(HttpHeaders.CACHE_CONTROL);
                assertThat(refused.getBody()).isNull();
            }
            upstream.verify(); upstream.reset();
            upstream.expect(requestTo("http://identity:8080" + path)).andRespond(withStatus(HttpStatus.CONFLICT).contentType(MediaType.APPLICATION_JSON).body("{\"code\":\"EXPECTED_ERROR\"}"));
            var forwarded = proxy.signIns(new MockHttpServletRequest("GET", path));
            assertThat(forwarded.getStatusCode().value()).isEqualTo(409);
            assertThat(new String(forwarded.getBody(), StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"EXPECTED_ERROR\"}");
            upstream.verify(); upstream.reset();
        }
    }

    @Test void forwardReadsAtMostTheAccountLimitAndRefusesALargerBodyBeforeIdentityIsAsked() throws Exception {
        assertThat(AccountIdentityProxy.MAX_ACCOUNT_BYTES).isEqualTo(8192);
        var exact = new MockHttpServletRequest("POST", "/api/v1/account/preferences");
        exact.setContent(new byte[AccountIdentityProxy.MAX_ACCOUNT_BYTES]);
        upstream.expect(requestTo("http://identity:8080/api/v1/account/preferences")).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(proxy.forward(exact).getStatusCode().value()).isEqualTo(200);
        var large = new MockHttpServletRequest("POST", "/api/v1/account/preferences");
        large.setContent(new byte[AccountIdentityProxy.MAX_ACCOUNT_BYTES + 1]);
        assertThat(proxy.forward(large).getStatusCode().value()).isEqualTo(413);
    }

    @Test void aChangedPasswordEndsTheSessionAndAddsTheExpiryCookieAfterIdentitysOwn() throws Exception {
        var session = new MockHttpSession();
        var request = signedIn("/api/v1/account/password", session);
        upstream.expect(requestTo(PASSWORD)).andRespond(withSuccess("{\"data\":{}}", MediaType.APPLICATION_JSON)
                .header("Set-Cookie", "IDENTITY_TEST=; Path=/; Max-Age=0; HttpOnly"));
        var response = proxy.password(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).isEqualTo("{\"data\":{}}");
        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).containsExactly("IDENTITY_TEST=; Path=/; Max-Age=0; HttpOnly",
                "LOOKAHEAD_GATEWAY=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax");
    }

    @Test void aChangedPasswordWithoutASessionCreatesNoneAndARefusedChangeKeepsTheSession() throws Exception {
        var anonymous = new MockHttpServletRequest("POST", "/api/v1/account/password");
        upstream.expect(requestTo(PASSWORD)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(proxy.password(anonymous).getHeaders().get(HttpHeaders.SET_COOKIE)).hasSize(1);
        assertThat(anonymous.getSession(false)).isNull();
        for (int status : new int[]{204, 401, 500}) {
            upstream.verify(); upstream.reset();
            var session = new MockHttpSession();
            var request = signedIn("/api/v1/account/password", session);
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            upstream.expect(requestTo(PASSWORD)).andRespond(withStatus(HttpStatus.valueOf(status)));
            var response = proxy.password(request);
            assertThat(response.getStatusCode().value()).isEqualTo(status == 500 ? 503 : status);
            assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
            assertThat(session.isInvalid()).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(authentication);
        }
    }

    @Test void theExpiryCookieIsBuiltOnceFromTheSessionCookieSettings() throws Exception {
        var custom = new AccountIdentityProxy(identity, new MockEnvironment()
                .withProperty("server.servlet.session.cookie.name", "GATEWAY_TEST")
                .withProperty("server.servlet.session.cookie.path", "/app")
                .withProperty("server.servlet.session.cookie.secure", "false")
                .withProperty("server.servlet.session.cookie.same-site", "Strict")
                .withProperty("server.servlet.session.cookie.domain", "example.test"));
        upstream.expect(requestTo(PASSWORD)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(custom.password(new MockHttpServletRequest("POST", "/api/v1/account/password")).getHeaders().get(HttpHeaders.SET_COOKIE))
                .containsExactly("GATEWAY_TEST=; Path=/app; Domain=example.test; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict");
        upstream.verify(); upstream.reset();
        // A blank domain is the same as none.
        var blank = new AccountIdentityProxy(identity, new MockEnvironment().withProperty("server.servlet.session.cookie.domain", " "));
        upstream.expect(requestTo(PASSWORD)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        assertThat(blank.password(new MockHttpServletRequest("POST", "/api/v1/account/password")).getHeaders().getFirst(HttpHeaders.SET_COOKIE))
                .isEqualTo("LOOKAHEAD_GATEWAY=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax");
    }

    @Test void aSignInUpdateEndsTheSessionOnlyWhenIdentityAsksForANewSignIn() throws Exception {
        String[] kept = {"{\"data\":{\"reauthenticationRequired\":false}}", "{\"data\":{}}", "{}", "[]"};
        for (String body : kept) {
            upstream.verify(); upstream.reset();
            var session = new MockHttpSession();
            var request = signedIn("/api/v1/account/sign-ins/revoke", session);
            upstream.expect(requestTo(REVOKE)).andRespond(withSuccess(body, MediaType.APPLICATION_JSON));
            var response = proxy.updateSignIns(request);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
            assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).isEqualTo(body);
            assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
            assertThat(session.isInvalid()).isFalse();
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        }
        upstream.verify(); upstream.reset();
        var session = new MockHttpSession();
        var request = signedIn("/api/v1/account/sign-ins/revoke", session);
        String asked = "{\"data\":{\"reauthenticationRequired\":true}}";
        upstream.expect(requestTo(REVOKE)).andRespond(withSuccess(asked, MediaType.APPLICATION_JSON));
        var response = proxy.updateSignIns(request);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(new String(response.getBody(), StandardCharsets.UTF_8)).isEqualTo(asked);
        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).containsExactly(
                "LOOKAHEAD_GATEWAY=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Secure; HttpOnly; SameSite=Lax");
        assertThat(session.isInvalid()).isTrue();
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test void aSignInUpdateThatIdentityRefusesOrFailsIsAnsweredWithoutReadingItsBody() throws Exception {
        for (int status : new int[]{409, 500}) {
            upstream.verify(); upstream.reset();
            var session = new MockHttpSession();
            var request = signedIn("/api/v1/account/sign-ins/revoke", session);
            upstream.expect(requestTo(REVOKE)).andRespond(withStatus(HttpStatus.valueOf(status)).body("{\"data\":{\"reauthenticationRequired\":true}}"));
            var response = proxy.updateSignIns(request);
            assertThat(response.getStatusCode().value()).isEqualTo(status == 500 ? 503 : status);
            assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
            assertThat(session.isInvalid()).isFalse();
        }
    }

    @Test void aSignInUpdateAnswerThatIsNotJsonIsAnswered503WithOneWarnLineAndTheSessionKept() throws Exception {
        try (var log = new LogCapture("lookahead.event")) {
            var session = new MockHttpSession();
            var request = signedIn("/api/v1/account/sign-ins/label", session);
            upstream.expect(requestTo("http://identity:8080/api/v1/account/sign-ins/label"))
                    .andRespond(withSuccess("synthetic-body-secret is not json", MediaType.APPLICATION_JSON));
            var response = proxy.updateSignIns(request);
            assertThat(response.getStatusCode().value()).isEqualTo(503);
            assertThat(response.getHeaders().getFirst(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
            assertThat(response.getBody()).isNull();
            assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE)).isNull();
            assertThat(session.isInvalid()).isFalse();
            assertThat(log.lines()).hasSize(1);
            assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
            assertThat(LogCapture.pairs(log.last())).contains("event.action=account.identity", "reason=IDENTITY_ANSWER_NOT_JSON",
                    "upstream.service=identity", "url.path=/api/v1/account/sign-ins/label");
            assertThat(log.last().getFormattedMessage())
                    .startsWith("Identity's answer to POST /api/v1/account/sign-ins/label was unusable: IDENTITY_ANSWER_NOT_JSON (not readable JSON: ")
                    .endsWith("); answered 503");
            log.assertNothing("synthetic-body-secret");
        }
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

    @Test void identityAnswersTooLargeOrNotJsonAreNamed() throws Exception {
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        var oauth = new OAuthClientDetails("http://127.0.0.1:4350", "lookahead-test", "synthetic-client-secret-only-for-testing",
                "http://identity:8080", "http://domain-api:8080", "http://127.0.0.1:4350");
        var identity = new IdentityProxy(oauth, builder.build(), "IDENTITY_TEST", "LOOKAHEAD_SIGNIN_BINDING", "LOOKAHEAD_SIGNIN_CHALLENGE", "LOOKAHEAD_GATEWAY");
        var account = new AccountIdentityController(new AccountIdentityProxy(identity, new MockEnvironment().withProperty("server.servlet.session.cookie.secure", "false")));
        server.expect(requestTo("http://identity:8080/api/v1/account/profile")).andRespond(withSuccess("x".repeat(AccountIdentityProxy.MAX_ACCOUNT_BYTES + 1), MediaType.TEXT_PLAIN));
        server.expect(requestTo("http://identity:8080/api/v1/account/sign-ins/label")).andRespond(withSuccess(SECRET + " is not json", MediaType.APPLICATION_JSON));
        assertThat(account.profile(new MockHttpServletRequest("GET", "/api/v1/account/profile")).getStatusCode().value()).isEqualTo(503);
        reason("identity.proxy", "IDENTITY_ANSWER_TOO_LARGE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Identity answer for GET /api/v1/account/profile refused with 502: IDENTITY_ANSWER_TOO_LARGE (larger than 8192 bytes)");
        assertThat(account.updateSignIns(new MockHttpServletRequest("POST", "/api/v1/account/sign-ins/label")).getStatusCode().value()).isEqualTo(503);
        reason("account.identity", "IDENTITY_ANSWER_NOT_JSON");
        assertThat(log.last().getFormattedMessage()).startsWith("Identity's answer to POST /api/v1/account/sign-ins/label was unusable: IDENTITY_ANSWER_NOT_JSON (not readable JSON: ");
        server.verify();
    }
    }
}
