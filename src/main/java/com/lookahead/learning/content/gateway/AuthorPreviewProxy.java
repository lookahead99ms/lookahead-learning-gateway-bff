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
        if (token == null || token.isBlank()) return empty(401);
        if (!method.equals("GET") && !method.equals("HEAD")) return empty(405);
        final URI target;
        try {
            target = AuthorPreviewPath.target(settings.upstream(), path, query);
        } catch (IllegalArgumentException error) {
            return empty(400);
        }
        try {
            int access = http.get().uri(URI.create(oauth.platformUpstream() + "/api/v1/author/previews/access"))
                    .headers(headers -> headers.setBearerAuth(token))
                    .exchange((sent, received) -> received.getStatusCode().value());
            if (access != 204) return empty(access == 401 || access == 403 ? access : 503);
            return http.method(HttpMethod.valueOf(method)).uri(target)
                    .header(SOURCE_KEY_HEADER, settings.upstreamSecret())
                    .exchange((sent, received) -> {
                        int status = received.getStatusCode().value();
                        if (status == 404) return empty(404);
                        if (status != 200) return empty(status >= 500 ? 503 : 502);
                        if (received.getHeaders().getContentLength() > MAX_BYTES) return empty(502);
                        byte[] bytes = method.equals("HEAD") ? new byte[0] : received.getBody().readNBytes(MAX_BYTES + 1);
                        if (bytes.length > MAX_BYTES) return empty(502);
                        var headers = responseHeaders();
                        MediaType type;
                        try {
                            type = received.getHeaders().getContentType();
                        } catch (IllegalArgumentException error) {
                            return empty(502);
                        }
                        headers.setContentType(type == null ? MediaType.APPLICATION_OCTET_STREAM : type);
                        // A servlet HEAD response may commit before deferred security header writers run.
                        GatewayFrameHeaders.applyPolicy(headers::set, type != null && MediaType.TEXT_HTML.isCompatibleWith(type));
                        return ResponseEntity.ok().headers(headers).body(bytes);
                    });
        } catch (RestClientException error) {
            return empty(503);
        }
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
