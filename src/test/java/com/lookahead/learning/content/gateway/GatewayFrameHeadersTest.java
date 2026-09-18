package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import static org.junit.jupiter.api.Assertions.assertEquals;

class GatewayFrameHeadersTest {
    @Test void onlySuccessfulPreviewHtmlAllowsSameOriginFrames() {
        for (String method : new String[]{"GET", "HEAD"}) {
            var response = new MockHttpServletResponse();
            response.setContentType("text/html;charset=UTF-8");
            new GatewayFrameHeaders().writeHeaders(
                    new MockHttpServletRequest(method, "/bff/author/previews/example/index.html"), response);
            assertEquals("SAMEORIGIN", response.getHeader("X-Frame-Options"));
            assertEquals("frame-ancestors 'self'", response.getHeader("Content-Security-Policy"));
        }
        for (int status : new int[]{401, 403, 404, 503}) {
            var response = new MockHttpServletResponse();
            response.setStatus(status);
            response.setContentType("text/html");
            new GatewayFrameHeaders().writeHeaders(
                    new MockHttpServletRequest("GET", "/bff/author/previews/example/index.html"), response);
            assertEquals("DENY", response.getHeader("X-Frame-Options"));
        }
    }
    @Test void teachingHtmlAllowsOnlySameOriginAncestors() {
        var response = new MockHttpServletResponse();
        new GatewayFrameHeaders().writeHeaders(
                new MockHttpServletRequest("GET", "/content/grow/example/visuals/lab.html"), response);
        assertEquals("SAMEORIGIN", response.getHeader("X-Frame-Options"));
        assertEquals("frame-ancestors 'self'", response.getHeader("Content-Security-Policy"));
    }
    @Test void accountRoutesJsonAndMutationsCannotBeFramed() {
        for (var path : new String[]{"/bff/api/v1/auth/me", "/content/details/answer.json", "/untrusted/lab.html"}) {
            var response = new MockHttpServletResponse();
            new GatewayFrameHeaders().writeHeaders(new MockHttpServletRequest("GET", path), response);
            assertEquals("DENY", response.getHeader("X-Frame-Options"));
            assertEquals("frame-ancestors 'none'", response.getHeader("Content-Security-Policy"));
        }
        var response = new MockHttpServletResponse();
        new GatewayFrameHeaders().writeHeaders(new MockHttpServletRequest("POST", "/content/lab.html"), response);
        assertEquals("DENY", response.getHeader("X-Frame-Options"));
    }
}
