package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class AuthorPreviewProxyTest {
    private static final String ACCESS = "http://domain-api:8080/api/v1/author/previews/access";
    private static final String PATH = AuthorPreviewPath.PREFIX + "preview-directory/manifest.json";
    private static final String SOURCE = "http://127.0.0.1:4315/preview-directory/manifest.json";
    private static final String TOKEN = "synthetic-server-held-access-token";
    private MockRestServiceServer server;
    private AuthorPreviewProxy proxy;

    @BeforeEach void setup() {
        var builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        proxy = new AuthorPreviewProxy(new AuthorPreviewSettings(URI.create("http://127.0.0.1:4315"),
                AuthorPreviewSettingsTest.SOURCE_SECRET), AuthorPreviewSettingsTest.OAUTH, builder.build());
    }

    @Test void authorizesWithTheServerTokenThenFetchesBytesUsingOnlyTheSourceKey() {
        byte[] artifact = "{\"title\":\"Synthetic preview — UTF-8\"}".getBytes(StandardCharsets.UTF_8);
        expectAccess(204);
        server.expect(requestTo(SOURCE + "?theme=dark&name=a%20b"))
                .andExpect(method(HttpMethod.GET)).andExpect(request -> {
                    assertThat(request.getHeaders().getFirst(AuthorPreviewProxy.SOURCE_KEY_HEADER))
                            .isEqualTo(AuthorPreviewSettingsTest.SOURCE_SECRET);
                    assertThat(request.getHeaders().toSingleValueMap()).doesNotContainKeys(HttpHeaders.AUTHORIZATION, HttpHeaders.COOKIE,
                            "X-Forwarded-Host", "X-Author", "X-Account-Id");
                }).andRespond(withSuccess(artifact, MediaType.APPLICATION_JSON)
                        .header(HttpHeaders.SET_COOKIE, "source-session=private")
                        .header(HttpHeaders.LOCATION, "https://other.test/")
                        .header(AuthorPreviewProxy.SOURCE_KEY_HEADER, "must-not-leak")
                        .header(HttpHeaders.CACHE_CONTROL, "public, max-age=86400"));
        var response = proxy.fetch("GET", PATH, "theme=dark&name=a%20b", TOKEN);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(artifact);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeaders().getFirst("Referrer-Policy")).isEqualTo("no-referrer");
        assertThat(response.getHeaders().toSingleValueMap()).doesNotContainKeys(HttpHeaders.SET_COOKIE, HttpHeaders.LOCATION,
                AuthorPreviewProxy.SOURCE_KEY_HEADER, HttpHeaders.AUTHORIZATION);
        server.verify();
    }

    @Test void deniedOrUnavailableAuthorizationNeverFetchesTheSource() {
        for (int access : new int[]{401, 403, 200, 302, 404, 500, 503}) {
            server.reset();
            expectAccess(access);
            var response = proxy.fetch("GET", PATH, null, TOKEN);
            assertThat(response.getStatusCode().value()).isEqualTo(access == 401 || access == 403 ? access : 503);
            assertThat(response.getBody()).isEmpty();
            assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
            server.verify();
        }
        server.reset();
        server.expect(requestTo(ACCESS)).andRespond(withException(new IOException("synthetic unavailable API")));
        assertThat(proxy.fetch("GET", PATH, null, TOKEN).getStatusCode().value()).isEqualTo(503);
        server.verify();
    }

    @Test void rechecksAuthorCapabilityAndGrantsForEveryArtifactRequest() {
        expectAccess(204);
        server.expect(requestTo(SOURCE)).andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));
        expectAccess(403);
        assertThat(proxy.fetch("GET", PATH, null, TOKEN).getStatusCode().value()).isEqualTo(200);
        var revoked = proxy.fetch("GET", PATH, null, TOKEN);
        assertThat(revoked.getStatusCode().value()).isEqualTo(403);
        assertThat(revoked.getBody()).isEmpty();
        server.verify();
    }

    @Test void rejectsMissingCredentialsInvalidPathsAndUnsupportedMethodsBeforeNetworkAccess() {
        for (String token : new String[]{null, "", " "}) {
            assertThat(proxy.fetch("GET", PATH, null, token).getStatusCode().value()).isEqualTo(401);
        }
        assertThat(proxy.fetch("POST", PATH, null, TOKEN).getStatusCode().value()).isEqualTo(405);
        assertThat(proxy.fetch("GET", AuthorPreviewPath.PREFIX + "%252e%252e/secret", null, TOKEN)
                .getStatusCode().value()).isEqualTo(400);
        assertThat(proxy.fetch("GET", PATH, "q=%0d%0a", TOKEN).getStatusCode().value()).isEqualTo(400);
        server.verify();
    }

    @Test void headChecksAuthorizationAndSourceButReturnsNoBody() {
        expectAccess(204);
        server.expect(requestTo(SOURCE)).andExpect(method(HttpMethod.HEAD))
                .andRespond(withSuccess("must not return this body", MediaType.TEXT_HTML));
        var response = proxy.fetch("HEAD", PATH, null, TOKEN);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEmpty();
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.TEXT_HTML);
        server.verify();
    }

    @Test void preservesStaticContentTypesAndProvidesABinaryFallback() {
        for (String type : new String[]{"text/html;charset=UTF-8", "text/css", "application/javascript",
                "image/svg+xml", "image/png", "font/woff2", null}) {
            server.reset();
            expectAccess(204);
            var upstream = withStatus(HttpStatus.OK).body(new byte[]{0, 1, 2, (byte) 255});
            if (type != null) upstream.contentType(MediaType.parseMediaType(type));
            server.expect(requestTo(SOURCE)).andRespond(upstream);
            var response = proxy.fetch("GET", PATH, null, TOKEN);
            assertThat(response.getHeaders().getContentType()).isEqualTo(type == null
                    ? MediaType.APPLICATION_OCTET_STREAM : MediaType.parseMediaType(type));
            assertThat(response.getBody()).containsExactly(0, 1, 2, (byte) 255);
            server.verify();
        }
    }

    @Test void hidesSourceFailureBodiesAndRejectsRedirectsWithoutFollowingThem() {
        for (int sourceStatus : new int[]{301, 302, 307, 308, 401, 403, 404, 500, 503}) {
            server.reset();
            expectAccess(204);
            server.expect(requestTo(SOURCE)).andRespond(withStatus(HttpStatus.valueOf(sourceStatus))
                    .header(HttpHeaders.LOCATION, "http://other.test/private")
                    .body("private artifact or source diagnostics"));
            var response = proxy.fetch("GET", PATH, null, TOKEN);
            assertThat(response.getStatusCode().value()).isEqualTo(sourceStatus == 404 ? 404 : sourceStatus >= 500 ? 503 : 502);
            assertThat(response.getBody()).isEmpty();
            assertThat(response.getHeaders().toSingleValueMap()).doesNotContainKey(HttpHeaders.LOCATION);
            server.verify();
        }
        server.reset();
        expectAccess(204);
        server.expect(requestTo(SOURCE)).andRespond(withException(new IOException("synthetic unavailable source")));
        assertThat(proxy.fetch("GET", PATH, null, TOKEN).getStatusCode().value()).isEqualTo(503);
        server.verify();
    }

    @Test void malformedSourceContentTypeReturnsASafeEmptyGatewayError() {
        expectAccess(204);
        server.expect(requestTo(SOURCE)).andRespond(withStatus(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, "invalid-content-type")
                .body("private preview bytes must not leak on a malformed source response"));
        var response = proxy.fetch("GET", PATH, null, TOKEN);
        assertThat(response.getStatusCode().value()).isEqualTo(502);
        assertThat(response.getBody()).isEmpty();
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("private, no-store");
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        server.verify();
    }

    @Test void boundsBodiesEvenWhenContentLengthIsAbsentOrUnderreported() {
        byte[] oversized = new byte[AuthorPreviewProxy.MAX_BYTES + 1];
        for (String contentLength : new String[]{null, "1", String.valueOf(oversized.length)}) {
            server.reset();
            expectAccess(204);
            var upstream = withSuccess(oversized, MediaType.APPLICATION_OCTET_STREAM);
            if (contentLength != null) upstream.header(HttpHeaders.CONTENT_LENGTH, contentLength);
            server.expect(requestTo(SOURCE)).andRespond(upstream);
            var response = proxy.fetch("GET", PATH, null, TOKEN);
            assertThat(response.getStatusCode().value()).isEqualTo(502);
            assertThat(response.getBody()).isEmpty();
            server.verify();
        }
        server.reset();
        expectAccess(204);
        byte[] maximum = new byte[AuthorPreviewProxy.MAX_BYTES];
        maximum[maximum.length - 1] = 42;
        server.expect(requestTo(SOURCE)).andRespond(withSuccess(maximum, MediaType.APPLICATION_OCTET_STREAM));
        var response = proxy.fetch("GET", PATH, null, TOKEN);
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody()).isEqualTo(maximum);
        server.verify();
    }

    private void expectAccess(int status) {
        server.expect(requestTo(ACCESS)).andExpect(method(HttpMethod.GET)).andExpect(request -> {
            assertThat(request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer " + TOKEN);
            assertThat(request.getHeaders().toSingleValueMap()).doesNotContainKeys(AuthorPreviewProxy.SOURCE_KEY_HEADER, HttpHeaders.COOKIE);
        }).andRespond(withStatus(HttpStatus.valueOf(status)));
    }
}
