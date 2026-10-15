package com.lookahead.learning.content.gateway;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

/** Admission filter runs before this fallback; static Web never receives browser credentials. */
@RestController @Profile("lower-cost-dev")
public final class DevWebProxy {
    private final RestClient http;
    private final String origin;
    public DevWebProxy(RestClient http, @org.springframework.beans.factory.annotation.Value("${LOOKAHEAD_RELEASE_SLOT}") String slot) {
        this.http = http; this.origin = com.lookahead.learning.content.oauth.DevServiceOrigins.forSlot(slot).web();
    }
    @RequestMapping(value="/**", method={RequestMethod.GET, RequestMethod.HEAD})
    ResponseEntity<byte[]> get(HttpServletRequest request) {
        String path = request.getRequestURI();
        if (!safePath(path)) return ResponseEntity.notFound().build();
        // Static objects do not need the query string, cookies, Authorization or forwarding headers.
        return http.method(HttpMethod.valueOf(request.getMethod())).uri(java.net.URI.create(origin + path))
            .exchange((sent, received) -> {
                byte[] bytes = received.getBody().readNBytes(16 * 1024 * 1024 + 1);
                if (bytes.length > 16 * 1024 * 1024 || received.getStatusCode().is3xxRedirection()) return ResponseEntity.status(502).body(new byte[0]);
                var headers = new HttpHeaders(); headers.setCacheControl("no-store"); headers.set("X-Content-Type-Options", "nosniff");
                if (received.getHeaders().getContentType() != null) headers.setContentType(received.getHeaders().getContentType());
                return new ResponseEntity<>(bytes, headers, received.getStatusCode());
            });
    }
    static boolean safePath(String path) {
        return path != null && path.startsWith("/") && !path.contains("..") && !path.contains("%") && !path.contains("\\")
            && !path.contains(";") && !path.contains("//") && !path.matches("^/(api|bff|content|auth|oauth2|login|logout|dev|actuator|local-previews)(/.*)?$")
            && !path.matches(".*\\.(pem|key|p12|pfx|jks|map)$") && !path.contains("/.");
    }
}
