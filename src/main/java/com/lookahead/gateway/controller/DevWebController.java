package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.DevWebProxy;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** Admission filter runs before this fallback; static Web never receives browser credentials. */
@RestController
@Profile("lower-cost-dev")
public final class DevWebController {
  private final DevWebProxy proxy;

  public DevWebController(DevWebProxy proxy) {
    this.proxy = proxy;
  }

  @RequestMapping(
      value = "/**",
      method = {RequestMethod.GET, RequestMethod.HEAD})
  public ResponseEntity<byte[]> get(HttpServletRequest request) {
    return proxy.forward(request);
  }
}
