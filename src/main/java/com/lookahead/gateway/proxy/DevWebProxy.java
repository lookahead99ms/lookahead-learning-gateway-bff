package com.lookahead.gateway.proxy;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.util.DevServiceOrigins;
import com.lookahead.gateway.util.UpstreamAnswerHeaders;
import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import org.springframework.http.*;
import org.springframework.web.client.RestClient;

/**
 * Forwards one safe GET or HEAD path to the static Web and shapes its answer (a path it may not
 * serve is a 404 and never reaches the Web); the fallback route is in {@code DevWebController}.
 */
public final class DevWebProxy {
  private final RestClient http;
  private final String origin;

  public DevWebProxy(RestClient http, DevServiceOrigins origins) {
    // LOOKAHEAD_WEB_UPSTREAM, validated against the stable Web name (DLV-968 S3).
    this.http = http;
    this.origin = origins.web();
  }

  public ResponseEntity<byte[]> forward(HttpServletRequest request) {
    String path = request.getRequestURI();
    if (!safePath(path)) return ResponseEntity.notFound().build();
    // Static objects do not need the query string, cookies, Authorization or forwarding headers.
    return http.method(HttpMethod.valueOf(request.getMethod()))
        .uri(URI.create(origin + path))
        .exchange((sent, received) -> {
          byte[] bytes = received.getBody().readNBytes(16 * 1024 * 1024 + 1);
          if (bytes.length > 16 * 1024 * 1024 || received.getStatusCode().is3xxRedirection()) {
            // DLV-969: the browser only sees 502; the log says which rule refused Web's answer.
            boolean redirect = received.getStatusCode().is3xxRedirection();
            OpsLog.failed("web.proxy", redirect ? "WEB_REDIRECT_REFUSED" : "WEB_ANSWER_TOO_LARGE")
                .addKeyValue("upstream.service", "web")
                .addKeyValue("upstream.status", received.getStatusCode().value())
                .addKeyValue("url.path", OpsLog.path(request))
                .log(
                    "Web answer for {} {} refused with 502: {} ({})",
                    OpsLog.method(request),
                    OpsLog.path(request),
                    redirect ? "WEB_REDIRECT_REFUSED" : "WEB_ANSWER_TOO_LARGE",
                    redirect
                        ? "Web answered a redirect (HTTP "
                            + received.getStatusCode().value()
                            + "), which the Gateway never follows or relays"
                        : "larger than 16 MB");
            return ResponseEntity.status(502).body(new byte[0]);
          }
          var headers = UpstreamAnswerHeaders.from(received);
          return new ResponseEntity<>(bytes, headers, received.getStatusCode());
        });
  }

  public static boolean safePath(String path) {
    return path != null
        && path.startsWith("/")
        && !path.contains("..")
        && !path.contains("%")
        && !path.contains("\\")
        && !path.contains(";")
        && !path.contains("//")
        && !path.matches(
            "^/(api|bff|content|auth|oauth2|login|logout|dev|actuator|local-previews)(/.*)?$")
        && !path.matches(".*\\.(pem|key|p12|pfx|jks|map)$")
        && !path.contains("/.");
  }
}
