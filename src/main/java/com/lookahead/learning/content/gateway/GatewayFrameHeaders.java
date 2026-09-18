package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;

/** Permit same-origin teaching and authorized preview frames; deny framing for other routes. */
public final class GatewayFrameHeaders implements HeaderWriter {
    @Override public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        String path = request.getRequestURI();
        boolean teachingHtml = request.getMethod().equals("GET")
                && path.startsWith("/content/") && path.endsWith(".html");
        boolean previewHtml = (request.getMethod().equals("GET") || request.getMethod().equals("HEAD"))
                && path.startsWith(AuthorPreviewPath.PREFIX) && response.getStatus() == 200
                && response.getContentType() != null && response.getContentType().startsWith("text/html");
        boolean sameOrigin = teachingHtml || previewHtml;
        applyPolicy(response::setHeader, sameOrigin);
    }

    static void applyPolicy(java.util.function.BiConsumer<String, String> setHeader, boolean sameOrigin) {
        setHeader.accept("X-Frame-Options", sameOrigin ? "SAMEORIGIN" : "DENY");
        setHeader.accept("Content-Security-Policy", "frame-ancestors " + (sameOrigin ? "'self'" : "'none'"));
    }
}
