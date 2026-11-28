package com.lookahead.gateway.controller;

import com.lookahead.gateway.proxy.AuthorPreviewProxy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Profile("gateway")
@ConditionalOnProperty(name = "app.author-previews.enabled", havingValue = "true")
public class AuthorPreviewController {
  private final AuthorPreviewProxy previews;

  AuthorPreviewController(AuthorPreviewProxy previews) {
    this.previews = previews;
  }

  @RequestMapping(
      value = "/bff/author/previews/**",
      method = {RequestMethod.GET, RequestMethod.HEAD})
  ResponseEntity<byte[]> preview(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
    return previews.preview(request, response, authentication);
  }
}
