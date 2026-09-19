package com.lookahead.learning.content.dto;

/** Browser CSRF metadata; OAuth access and refresh tokens remain server-side. */
public record CsrfView(String token, String headerName, String parameterName) {}
