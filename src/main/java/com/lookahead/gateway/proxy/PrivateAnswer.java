package com.lookahead.gateway.proxy;

import com.lookahead.gateway.security.handler.FramePolicyHeaderWriter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;

/**
 * The answer the forwarders give when they hand nothing over: no body, never stored, never sniffed, no referrer, no
 * framing. The author preview uses it for every refusal and failure and starts its own answers from the same headers;
 * the Domain relay uses it to refuse a test session on staff routes exactly as the previews do.
 */
public final class PrivateAnswer {
    private PrivateAnswer() {}

    public static ResponseEntity<byte[]> empty(int status) {
        return ResponseEntity.status(status).headers(responseHeaders()).body(new byte[0]);
    }

    static HttpHeaders responseHeaders() {
        var headers = new HttpHeaders();
        headers.setCacheControl("private, no-store");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "no-referrer");
        FramePolicyHeaderWriter.applyPolicy(headers::set, false);
        return headers;
    }
}
