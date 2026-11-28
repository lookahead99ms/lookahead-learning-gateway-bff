package com.lookahead.gateway.controller;

import com.lookahead.gateway.security.handler.DevAccessHandler;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.Map;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;

/** The DEV gate's own routes; what each of them answers is in {@code DevAccessHandler}. */
@RestController
@Profile("lower-cost-dev")
public final class DevAccessController {
  private final DevAccessHandler handler;

  public DevAccessController(DevAccessHandler handler) {
    this.handler = handler;
  }

  @GetMapping(value = "/dev/access", produces = "text/html")
  ResponseEntity<String> access(
      @RequestParam(required = false) String access, @RequestParam(required = false) String error) {
    return handler.access(access, error);
  }

  @GetMapping("/dev/csrf")
  ResponseEntity<Map<String, String>> csrf(CsrfToken token) {
    return handler.csrf(token);
  }

  @PostMapping("/dev/leave")
  ResponseEntity<Map<String, String>> leave(
      HttpServletRequest request, HttpServletResponse response) {
    return handler.leave(request, response);
  }

  @GetMapping("/dev/leave/complete")
  void complete(HttpServletResponse response) throws IOException {
    handler.complete(response);
  }
}
