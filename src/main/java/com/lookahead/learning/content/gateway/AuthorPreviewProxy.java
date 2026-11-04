package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import java.net.URI;

/** Recheck server capability and current catalog grants before each bounded artifact fetch. */
final class AuthorPreviewProxy {
    static final String SOURCE_KEY_HEADER = "X-LookAhead-Preview-Key";
    static final int MAX_BYTES = 16 * 1024 * 1024;
    private final AuthorPreviewSettings settings;
    private final OAuthSettings oauth;
    private final RestClient http;

    AuthorPreviewProxy(AuthorPreviewSettings settings, OAuthSettings oauth, RestClient http) {
        this.settings = settings;
        this.oauth = oauth;
        this.http = http;
    }

    ResponseEntity<byte[]> fetch(String method, String path, String query, String token) {
        return fetch(method,path,query,token,null);
    }

    ResponseEntity<byte[]> fetch(String method,String path,String query,String token,String proof) {
        if (token == null || token.isBlank()) return empty(401);
        if (!method.equals("GET") && !method.equals("HEAD")) return empty(405);
        final URI target;
        try {
            target = AuthorPreviewPath.target(settings.upstream(), path, query);
        } catch (IllegalArgumentException error) {
            return empty(400);
        }
        try {
            int access = http.get().uri(URI.create(oauth.domainApiUpstream() + "/api/v1/author/previews/access"))
                    .headers(headers -> {headers.setBearerAuth(token);if(oauth.cloud()&&proof!=null)headers.set("X-LookAhead-SignIn-Proof",proof);})
                    .exchange((sent, received) -> received.getStatusCode().value());
            if (access != 204) return access == 401 || access == 403
                    ? failed(access, "PREVIEW_ACCESS_REFUSED", "Domain refused author preview access (HTTP " + access + ")")
                    : failed(503, "PREVIEW_ACCESS_CHECK_FAILED", "Domain's author preview access check answered HTTP " + access + " instead of 204");
            return http.method(HttpMethod.valueOf(method)).uri(target)
                    .header(SOURCE_KEY_HEADER, settings.upstreamSecret())
                    .exchange((sent, received) -> {
                        int status = received.getStatusCode().value();
                        if (status == 404) return empty(404);
                        if (status != 200) return failed(status >= 500 ? 503 : 502, "PREVIEW_SERVER_HTTP_" + status,
                                "the local preview server answered HTTP " + status);
                        if (received.getHeaders().getContentLength() > MAX_BYTES) return failed(502, "PREVIEW_TOO_LARGE", "the artifact is larger than 16 MB");
                        byte[] bytes = method.equals("HEAD") ? new byte[0] : received.getBody().readNBytes(MAX_BYTES + 1);
                        if (bytes.length > MAX_BYTES) return failed(502, "PREVIEW_TOO_LARGE", "the artifact is larger than 16 MB");
                        var headers = responseHeaders();
                        MediaType type;
                        try {
                            type = received.getHeaders().getContentType();
                        } catch (IllegalArgumentException error) {
                            return failed(502, "PREVIEW_INVALID_CONTENT_TYPE", "the preview server sent an unreadable Content-Type");
                        }
                        headers.setContentType(type == null ? MediaType.APPLICATION_OCTET_STREAM : type);
                        // A servlet HEAD response may commit before deferred security header writers run.
                        GatewayFrameHeaders.applyPolicy(headers::set, type != null && MediaType.TEXT_HTML.isCompatibleWith(type));
                        return ResponseEntity.ok().headers(headers).body(bytes);
                    });
        } catch (RestClientException error) {
            return failed(503, "PREVIEW_UNAVAILABLE", "Domain or the local preview server did not answer (" + RequestLog.types(error) + ")");
        }
    }

    /** DLV-969: this proxy has its own HTTP client without the upstream log line, so each refusal says why here. */
    static ResponseEntity<byte[]> failed(int status, String reason, String words) {
        (status == 401 || status == 403 ? OpsLog.refused("author-preview.fetch", reason) : OpsLog.failed("author-preview.fetch", reason))
                .addKeyValue("http.status", status).log("Author preview answered {}: {} ({})", status, words, reason);
        return empty(status);
    }

    static ResponseEntity<byte[]> empty(int status) {
        return ResponseEntity.status(status).headers(responseHeaders()).body(new byte[0]);
    }

    private static HttpHeaders responseHeaders() {
        var headers = new HttpHeaders();
        headers.setCacheControl("private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "no-referrer");
        GatewayFrameHeaders.applyPolicy(headers::set, false);
        return headers;
    }
}
