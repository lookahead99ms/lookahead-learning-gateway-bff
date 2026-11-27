package com.lookahead.gateway.dto;

import org.springframework.security.web.csrf.CsrfToken;

/** Browser CSRF metadata; OAuth access and refresh tokens remain server-side. */
public record CsrfView(String token, String headerName, String parameterName) {
    /** What the CSRF routes answer for the token Spring Security holds for this session. */
    public static CsrfView from(CsrfToken token) {
        return new CsrfView(token.getToken(),token.getHeaderName(),token.getParameterName());
    }
}
