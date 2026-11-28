package com.lookahead.gateway.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.client.AuthorPreviewDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.AuthorPreviewPath;
import com.lookahead.gateway.util.AuthorPreviewUpstream;
import com.lookahead.gateway.util.AuthorPreviewUpstreamTest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;

class AuthorPreviewProxyTest {
  private static final String ACCESS = "http://domain-api:8080/api/v1/author/previews/access";
  private static final String PATH = AuthorPreviewPath.PREFIX + "preview-directory/manifest.json";
  private static final String SOURCE = "http://127.0.0.1:4315/preview-directory/manifest.json";
  private static final String TOKEN = "synthetic-server-held-access-token";
  private MockRestServiceServer server;
  private AuthorPreviewProxy proxy;
  private RestClient http;

  /**
   * The proxy over this test's connection, built as the configuration builds it: the Domain client
   * first.
   */
  private AuthorPreviewProxy proxy(OAuth2AuthorizedClientManager manager) {
    return new AuthorPreviewProxy(
        new AuthorPreviewUpstream(
            URI.create("http://127.0.0.1:4315"), AuthorPreviewUpstreamTest.SOURCE_SECRET),
        new AuthorPreviewDomainClient(AuthorPreviewUpstreamTest.OAUTH, http),
        new SignInTokenClient(manager),
        http);
  }

  @BeforeEach
  void setup() {
    var builder = RestClient.builder();
    server = MockRestServiceServer.bindTo(builder).build();
    http = builder.build();
    proxy = proxy(request -> null);
  }

  @Test
  void authorizesWithTheServerTokenThenFetchesBytesUsingOnlyTheSourceKey() {
    byte[] artifact = "{\"title\":\"Synthetic preview — UTF-8\"}".getBytes(StandardCharsets.UTF_8);
    expectAccess(204);
    server
        .expect(requestTo(SOURCE + "?theme=dark&name=a%20b"))
        .andExpect(method(HttpMethod.GET))
        .andExpect(request -> {
          assertThat(request.getHeaders().getFirst(AuthorPreviewProxy.SOURCE_KEY_HEADER))
              .isEqualTo(AuthorPreviewUpstreamTest.SOURCE_SECRET);
          assertThat(request.getHeaders().toSingleValueMap())
              .doesNotContainKeys(
                  HttpHeaders.AUTHORIZATION,
                  HttpHeaders.COOKIE,
                  "X-Forwarded-Host",
                  "X-Author",
                  "X-Account-Id");
        })
        .andRespond(
            withSuccess(artifact, MediaType.APPLICATION_JSON)
                .header(HttpHeaders.SET_COOKIE, "source-session=private")
                .header(HttpHeaders.LOCATION, "https://other.test/")
                .header(AuthorPreviewProxy.SOURCE_KEY_HEADER, "must-not-leak")
                .header(HttpHeaders.CACHE_CONTROL, "public, max-age=86400"));
    var response = proxy.fetch("GET", PATH, "theme=dark&name=a%20b", TOKEN, null);
    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(response.getBody()).isEqualTo(artifact);
    assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
    assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
    assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
    assertThat(response.getHeaders().getFirst("Referrer-Policy")).isEqualTo("no-referrer");
    assertThat(response.getHeaders().toSingleValueMap())
        .doesNotContainKeys(
            HttpHeaders.SET_COOKIE,
            HttpHeaders.LOCATION,
            AuthorPreviewProxy.SOURCE_KEY_HEADER,
            HttpHeaders.AUTHORIZATION);
    server.verify();
  }

  @Test
  void deniedOrUnavailableAuthorizationNeverFetchesTheSource() {
    for (int access : new int[] {401, 403, 200, 302, 404, 500, 503}) {
      server.reset();
      expectAccess(access);
      var response = proxy.fetch("GET", PATH, null, TOKEN, null);
      assertThat(response.getStatusCode().value())
          .isEqualTo(access == 401 || access == 403 ? access : 503);
      assertThat(response.getBody()).isEmpty();
      assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
      server.verify();
    }
    server.reset();
    server
        .expect(requestTo(ACCESS))
        .andRespond(withException(new IOException("synthetic unavailable API")));
    assertThat(proxy.fetch("GET", PATH, null, TOKEN, null).getStatusCode().value()).isEqualTo(503);
    server.verify();
  }

  @Test
  void rechecksAuthorCapabilityAndGrantsForEveryArtifactRequest() {
    expectAccess(204);
    server.expect(requestTo(SOURCE)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
    expectAccess(403);
    assertThat(proxy.fetch("GET", PATH, null, TOKEN, null).getStatusCode().value()).isEqualTo(200);
    var revoked = proxy.fetch("GET", PATH, null, TOKEN, null);
    assertThat(revoked.getStatusCode().value()).isEqualTo(403);
    assertThat(revoked.getBody()).isEmpty();
    server.verify();
  }

  @Test
  void rejectsMissingCredentialsInvalidPathsAndUnsupportedMethodsBeforeNetworkAccess() {
    for (String token : new String[] {null, "", " "}) {
      assertThat(proxy.fetch("GET", PATH, null, token, null).getStatusCode().value())
          .isEqualTo(401);
    }
    assertThat(proxy.fetch("POST", PATH, null, TOKEN, null).getStatusCode().value()).isEqualTo(405);
    assertThat(
            proxy
                .fetch("GET", AuthorPreviewPath.PREFIX + "%252e%252e/secret", null, TOKEN, null)
                .getStatusCode()
                .value())
        .isEqualTo(400);
    assertThat(proxy.fetch("GET", PATH, "q=%0d%0a", TOKEN, null).getStatusCode().value())
        .isEqualTo(400);
    server.verify();
  }

  @Test
  void headChecksAuthorizationAndSourceButReturnsNoBody() {
    expectAccess(204);
    server
        .expect(requestTo(SOURCE))
        .andExpect(method(HttpMethod.HEAD))
        .andRespond(withSuccess("must not return this body", MediaType.TEXT_HTML));
    var response = proxy.fetch("HEAD", PATH, null, TOKEN, null);
    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(response.getBody()).isEmpty();
    assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
    server.verify();
  }

  @Test
  void preservesStaticContentTypesAndProvidesABinaryFallback() {
    for (String type :
        new String[] {
          "text/html;charset=UTF-8",
          "text/css",
          "application/javascript",
          "image/svg+xml",
          "image/png",
          "font/woff2",
          null
        }) {
      server.reset();
      expectAccess(204);
      var upstream = withStatus(HttpStatus.OK).body(new byte[] {0, 1, 2, (byte) 255});
      if (type != null) upstream.contentType(MediaType.parseMediaType(type));
      server.expect(requestTo(SOURCE)).andRespond(upstream);
      var response = proxy.fetch("GET", PATH, null, TOKEN, null);
      assertThat(response.getHeaders().getContentType())
          .isEqualTo(
              type == null ? MediaType.APPLICATION_OCTET_STREAM : MediaType.parseMediaType(type));
      assertThat(response.getBody()).containsExactly(0, 1, 2, (byte) 255);
      server.verify();
    }
  }

  @Test
  void hidesSourceFailureBodiesAndRejectsRedirectsWithoutFollowingThem() {
    for (int sourceStatus : new int[] {301, 302, 307, 308, 401, 403, 404, 500, 503}) {
      server.reset();
      expectAccess(204);
      server
          .expect(requestTo(SOURCE))
          .andRespond(
              withStatus(HttpStatus.valueOf(sourceStatus))
                  .header(HttpHeaders.LOCATION, "http://other.test/private")
                  .body("private artifact or source diagnostics"));
      var response = proxy.fetch("GET", PATH, null, TOKEN, null);
      assertThat(response.getStatusCode().value())
          .isEqualTo(sourceStatus == 404 ? 404 : sourceStatus >= 500 ? 503 : 502);
      assertThat(response.getBody()).isEmpty();
      assertThat(response.getHeaders().toSingleValueMap()).doesNotContainKey(HttpHeaders.LOCATION);
      server.verify();
    }
    server.reset();
    expectAccess(204);
    server
        .expect(requestTo(SOURCE))
        .andRespond(withException(new IOException("synthetic unavailable source")));
    assertThat(proxy.fetch("GET", PATH, null, TOKEN, null).getStatusCode().value()).isEqualTo(503);
    server.verify();
  }

  @Test
  void malformedSourceContentTypeReturnsASafeEmptyGatewayError() {
    expectAccess(204);
    server
        .expect(requestTo(SOURCE))
        .andRespond(
            withStatus(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, "invalid-content-type")
                .body("private preview bytes must not leak on a malformed source response"));
    var response = proxy.fetch("GET", PATH, null, TOKEN, null);
    assertThat(response.getStatusCode().value()).isEqualTo(502);
    assertThat(response.getBody()).isEmpty();
    assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
    assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
    server.verify();
  }

  @Test
  void boundsBodiesEvenWhenContentLengthIsAbsentOrUnderreported() {
    byte[] oversized = new byte[AuthorPreviewProxy.MAX_BYTES + 1];
    for (String contentLength : new String[] {null, "1", String.valueOf(oversized.length)}) {
      server.reset();
      expectAccess(204);
      var upstream = withSuccess(oversized, MediaType.APPLICATION_OCTET_STREAM);
      if (contentLength != null) upstream.header(HttpHeaders.CONTENT_LENGTH, contentLength);
      server.expect(requestTo(SOURCE)).andRespond(upstream);
      var response = proxy.fetch("GET", PATH, null, TOKEN, null);
      assertThat(response.getStatusCode().value()).isEqualTo(502);
      assertThat(response.getBody()).isEmpty();
      server.verify();
    }
    server.reset();
    expectAccess(204);
    byte[] maximum = new byte[AuthorPreviewProxy.MAX_BYTES];
    maximum[maximum.length - 1] = 42;
    server
        .expect(requestTo(SOURCE))
        .andRespond(withSuccess(maximum, MediaType.APPLICATION_OCTET_STREAM));
    var response = proxy.fetch("GET", PATH, null, TOKEN, null);
    assertThat(response.getStatusCode().value()).isEqualTo(200);
    assertThat(response.getBody()).isEqualTo(maximum);
    server.verify();
  }

  // DLV-1015: the token renewal and its provider errors, moved here from
  // AuthorPreviewController.preview (statements unchanged).

  private static OAuth2AuthenticationToken principal() {
    var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
    return new OAuth2AuthenticationToken(
        new DefaultOAuth2User(authorities, Map.of("sub", "synthetic-author-subject"), "sub"),
        authorities,
        "lookahead");
  }

  private static OAuth2AuthorizedClient tokens() {
    var registration =
        ClientRegistration.withRegistrationId("lookahead")
            .clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize")
            .tokenUri("http://localhost/token")
            .build();
    return new OAuth2AuthorizedClient(
        registration,
        "synthetic-author-subject",
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            TOKEN,
            Instant.now(),
            Instant.now().plusSeconds(300)));
  }

  @Test
  void onlyAnAuthenticatedProviderSignInMayAskAndNobodyElseCostsARenewalOrALogLine() {
    var renewals = new AtomicInteger();
    var guarded =
        proxy(request -> {
          renewals.incrementAndGet();
          return tokens();
        });
    var unauthenticated = principal();
    unauthenticated.setAuthenticated(false);
    try (var log = new LogCapture("lookahead.event")) {
      for (Authentication authentication :
          new Authentication[] {
            null,
            unauthenticated,
            UsernamePasswordAuthenticationToken.authenticated(
                "author@lookahead.test", "ignored", List.of()),
            new TestSessionState.TestSession("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a")
          }) {
        var answer =
            guarded.preview(
                new MockHttpServletRequest("GET", PATH),
                new MockHttpServletResponse(),
                authentication);
        assertThat(answer.getStatusCode().value()).isEqualTo(401);
        assertThat(answer.getBody()).isEmpty();
        assertThat(answer.getHeaders().getCacheControl()).isEqualTo("private, no-store");
      }
      // A session without provider tokens is the same quiet 401.
      var none =
          proxy(request -> null)
              .preview(
                  new MockHttpServletRequest("GET", PATH),
                  new MockHttpServletResponse(),
                  principal());
      assertThat(none.getStatusCode().value()).isEqualTo(401);
      assertThat(none.getBody()).isEmpty();
      assertThat(log.lines()).isEmpty();
    }
    assertThat(renewals).hasValue(0);
    server.verify();
  }

  @Test
  void theRenewedTokenAndThisSessionsProofGoWithTheRequestsMethodPathAndQuery() {
    var request = new MockHttpServletRequest("HEAD", PATH);
    request.setQueryString("theme=dark");
    request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer browser-spoof-token");
    var response = new MockHttpServletResponse();
    var principal = principal();
    expectAccess(204);
    server
        .expect(requestTo(SOURCE + "?theme=dark"))
        .andExpect(method(HttpMethod.HEAD))
        .andRespond(withSuccess("ignored", MediaType.TEXT_HTML));
    var answer =
        proxy(
                asked -> {
                  assertThat(asked.getClientRegistrationId()).isEqualTo("lookahead");
                  assertThat(asked.getPrincipal()).isSameAs(principal);
                  assertThat(asked.getAttributes().get(HttpServletRequest.class.getName()))
                      .isSameAs(request);
                  assertThat(asked.getAttributes().get(HttpServletResponse.class.getName()))
                      .isSameAs(response);
                  return tokens();
                })
            .preview(request, response, principal);
    assertThat(answer.getStatusCode().value()).isEqualTo(200);
    assertThat(answer.getBody()).isEmpty();
    // Asking for the proof never creates a session.
    assertThat(request.getSession(false)).isNull();
    server.verify();
  }

  @Test
  void aRefusedRenewalIsAnswered401AndAnUnreachableProvider503EachWithItsOneWarnLine() {
    try (var log = new LogCapture("lookahead.event")) {
      String[][] refusals = {
        {"invalid_grant", "invalid_grant"}, {"Not A Code!", "unknown"}, {"x".repeat(65), "unknown"}
      };
      for (String[] refusal : refusals) {
        log.clear();
        var answer =
            proxy(
                    request -> {
                      throw new OAuth2AuthorizationException(
                          new OAuth2Error(refusal[0], "synthetic-secret-description", null));
                    })
                .preview(
                    new MockHttpServletRequest("GET", PATH),
                    new MockHttpServletResponse(),
                    principal());
        assertThat(answer.getStatusCode().value()).isEqualTo(401);
        assertThat(answer.getBody()).isEmpty();
        assertThat(log.lines()).hasSize(1);
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(log.last().getFormattedMessage())
            .isEqualTo(
                "Author preview answered 401: the provider refused to renew the sign-in ("
                    + refusal[1]
                    + ") (SESSION_EXPIRED)");
        assertThat(LogCapture.pairs(log.last()))
            .contains(
                "event.action=author-preview.fetch",
                "event.outcome=refused",
                "reason=SESSION_EXPIRED",
                "http.status=401");
        log.assertNothing("synthetic-secret-description");
      }
      log.clear();
      var down =
          proxy(
                  request -> {
                    throw new ResourceAccessException("synthetic-secret-description");
                  })
              .preview(
                  new MockHttpServletRequest("GET", PATH),
                  new MockHttpServletResponse(),
                  principal());
      assertThat(down.getStatusCode().value()).isEqualTo(503);
      assertThat(down.getBody()).isEmpty();
      assertThat(log.lines()).hasSize(1);
      assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
      assertThat(log.last().getFormattedMessage())
          .isEqualTo(
              "Author preview answered 503: the sign-in could not be renewed"
                  + " (ResourceAccessException) (TOKEN_REFRESH_UNAVAILABLE)");
      assertThat(LogCapture.pairs(log.last()))
          .contains(
              "event.action=author-preview.fetch",
              "reason=TOKEN_REFRESH_UNAVAILABLE",
              "http.status=503");
      log.assertNothing("synthetic-secret-description");
    }
    server.verify();
  }

  private void expectAccess(int status) {
    server
        .expect(requestTo(ACCESS))
        .andExpect(method(HttpMethod.GET))
        .andExpect(request -> {
          assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
              .isEqualTo("Bearer " + TOKEN);
          assertThat(request.getHeaders().toSingleValueMap())
              .doesNotContainKeys(AuthorPreviewProxy.SOURCE_KEY_HEADER, HttpHeaders.COOKIE);
        })
        .andRespond(withStatus(HttpStatus.valueOf(status)));
  }
}
