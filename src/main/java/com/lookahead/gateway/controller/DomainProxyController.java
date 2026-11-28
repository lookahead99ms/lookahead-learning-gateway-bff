package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.DomainProxy;
import jakarta.servlet.http.*;
import java.io.IOException;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@Profile("gateway")
public class DomainProxyController {
  private final DomainProxy forwarder;

  public DomainProxyController(DomainProxy forwarder) {
    this.forwarder = forwarder;
  }

  @RequestMapping(
      value = {"/bff/api/v1/**", "/content/**"},
      method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE})
  public ResponseEntity<byte[]> proxy(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException {
    return forwarder.relay(request, response, authentication);
  }
}
