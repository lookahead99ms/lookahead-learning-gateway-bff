package com.lookahead.gateway.proxy;

import com.lookahead.gateway.client.AuthorPreviewDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.handler.FramePolicyHeaderWriter;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.util.AuthorPreviewPath;
import com.lookahead.gateway.util.AuthorPreviewUpstream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import java.net.URI;

/** Recheck server capability and current catalog grants before each bounded artifact fetch. */
public final class AuthorPreviewProxy {
    public static final String SOURCE_KEY_HEADER = "X-LookAhead-Preview-Key";
    public static final int MAX_BYTES = 16 * 1024 * 1024;
    private final AuthorPreviewUpstream upstream;
    private final AuthorPreviewDomainClient domain;
    private final SignInTokenClient tokens;
    private final RestClient http;

    public AuthorPreviewProxy(AuthorPreviewUpstream upstream, AuthorPreviewDomainClient domain, SignInTokenClient tokens, RestClient http) {
        this.upstream = upstream;
        this.domain = domain;
        this.tokens = tokens;
        this.http = http;
    }

    /** One preview request of the route: only a provider sign-in may ask, its token is renewed first, then {@link #fetch}. */
    public ResponseEntity<byte[]> preview(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        if (!(authentication instanceof OAuth2AuthenticationToken) || !authentication.isAuthenticated()) {
            return PrivateAnswer.empty(401);
        }
        try {
            var client = tokens.authorize(authentication, request, response);
            if (client == null) return PrivateAnswer.empty(401);
            return fetch(request.getMethod(), request.getRequestURI(), request.getQueryString(),
                    client.getAccessToken().getTokenValue(),SignInProofSession.proof(request,false));
        } catch (OAuth2AuthorizationException error) {
            String code = OpsLog.oauthCode(error.getError(), "unknown");
            return failed(401, "SESSION_EXPIRED", "the provider refused to renew the sign-in (" + code + ")");
        } catch (RestClientException error) {
            return failed(503, "TOKEN_REFRESH_UNAVAILABLE", "the sign-in could not be renewed (" + OpsLog.types(error) + ")");
        }
    }

    public ResponseEntity<byte[]> fetch(String method,String path,String query,String token,String proof) {
        if (token == null || token.isBlank()) return PrivateAnswer.empty(401);
        if (!method.equals("GET") && !method.equals("HEAD")) return PrivateAnswer.empty(405);
        final URI target;
        try {
            target = AuthorPreviewPath.target(upstream.upstream(), path, query);
        } catch (IllegalArgumentException error) {
            return PrivateAnswer.empty(400);
        }
        try {
            int access = domain.access(token, proof);
            if (access != 204) return access == 401 || access == 403
                    ? failed(access, "PREVIEW_ACCESS_REFUSED", "Domain refused author preview access (HTTP " + access + ")")
                    : failed(503, "PREVIEW_ACCESS_CHECK_FAILED", "Domain's author preview access check answered HTTP " + access + " instead of 204");
            return http.method(HttpMethod.valueOf(method)).uri(target)
                    .header(SOURCE_KEY_HEADER, upstream.upstreamSecret())
                    .exchange((sent, received) -> {
                        int status = received.getStatusCode().value();
                        if (status == 404) return PrivateAnswer.empty(404);
                        if (status != 200) return failed(status >= 500 ? 503 : 502, "PREVIEW_SERVER_HTTP_" + status,
                                "the local preview server answered HTTP " + status);
                        if (received.getHeaders().getContentLength() > MAX_BYTES) return failed(502, "PREVIEW_TOO_LARGE", "the artifact is larger than 16 MB");
                        byte[] bytes = method.equals("HEAD") ? new byte[0] : received.getBody().readNBytes(MAX_BYTES + 1);
                        if (bytes.length > MAX_BYTES) return failed(502, "PREVIEW_TOO_LARGE", "the artifact is larger than 16 MB");
                        var headers = PrivateAnswer.responseHeaders();
                        MediaType type;
                        try {
                            type = received.getHeaders().getContentType();
                        } catch (IllegalArgumentException error) {
                            return failed(502, "PREVIEW_INVALID_CONTENT_TYPE", "the preview server sent an unreadable Content-Type");
                        }
                        headers.setContentType(type == null ? MediaType.APPLICATION_OCTET_STREAM : type);
                        // A servlet HEAD response may commit before deferred security header writers run.
                        FramePolicyHeaderWriter.applyPolicy(headers::set, type != null && MediaType.TEXT_HTML.isCompatibleWith(type));
                        return ResponseEntity.ok().headers(headers).body(bytes);
                    });
        } catch (RestClientException error) {
            return failed(503, "PREVIEW_UNAVAILABLE", "Domain or the local preview server did not answer (" + OpsLog.types(error) + ")");
        }
    }

    /** DLV-969: this proxy has its own HTTP client without the upstream log line, so each refusal says why here. */
    public static ResponseEntity<byte[]> failed(int status, String reason, String words) {
        (status == 401 || status == 403 ? OpsLog.refused("author-preview.fetch", reason) : OpsLog.failed("author-preview.fetch", reason))
                .addKeyValue("http.status", status).log("Author preview answered {}: {} ({})", status, words, reason);
        return PrivateAnswer.empty(status);
    }

}
