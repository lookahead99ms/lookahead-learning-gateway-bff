package com.lookahead.gateway.util;

import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ClientHttpResponse;

/** The headers a forwarder puts on the browser's answer when it passes an upstream's body through: never cached, never sniffed, the upstream's content type. */
public final class UpstreamAnswerHeaders {
    private UpstreamAnswerHeaders() {}

    public static HttpHeaders from(ClientHttpResponse received) {
        var headers = new HttpHeaders(); headers.setCacheControl("no-store"); headers.set("X-Content-Type-Options", "nosniff");
        if (received.getHeaders().getContentType() != null) headers.setContentType(received.getHeaders().getContentType());
        return headers;
    }
}
