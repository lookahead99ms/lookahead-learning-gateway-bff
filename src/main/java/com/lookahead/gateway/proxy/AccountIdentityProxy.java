package com.lookahead.gateway.proxy;

import com.lookahead.gateway.log.OpsLog;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import tools.jackson.databind.json.JsonMapper;

/**
 * Forwards the self-only account operations to the Identity service through {@link IdentityProxy} and shapes what comes
 * back for the browser: an infrastructure error becomes a plain 503, and a changed password or a revocation that needs a
 * new sign-in ends this application's session and expires its cookie. The routes are in {@code AccountIdentityController}.
 */
public final class AccountIdentityProxy {
    public static final int MAX_ACCOUNT_BYTES = 8192;
    private final IdentityProxy identity;
    private final String expiredSessionCookie;

    public AccountIdentityProxy(IdentityProxy identity, Environment environment) {
        this.identity = identity;
        var cookie = ResponseCookie.from(environment.getProperty("server.servlet.session.cookie.name", "LOOKAHEAD_GATEWAY"), "")
                .path(environment.getProperty("server.servlet.session.cookie.path", "/"))
                .httpOnly(true)
                .secure(environment.getProperty("server.servlet.session.cookie.secure", Boolean.class, true))
                .sameSite(environment.getProperty("server.servlet.session.cookie.same-site", "Lax"))
                .maxAge(0);
        String domain = environment.getProperty("server.servlet.session.cookie.domain");
        if (domain != null && !domain.isBlank()) cookie.domain(domain);
        expiredSessionCookie = cookie.build().toString();
    }

    /** The profile route: read and update. Any other method is answered here with 405 and never reaches Identity. */
    public ResponseEntity<byte[]> profile(HttpServletRequest request) throws IOException {
        // Spring maps HEAD implicitly to GET; only the published methods reach Identity.
        if (!"GET".equals(request.getMethod()) && !"POST".equals(request.getMethod()))
            return ResponseEntity.status(405).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
        return forward(request);
    }

    /** The two read-only routes (the sign-in list and the sign-in challenge): GET only, any other method is a 405 here. */
    public ResponseEntity<byte[]> signIns(HttpServletRequest request) throws IOException {
        if (!"GET".equals(request.getMethod()))
            return ResponseEntity.status(405).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
        return forward(request);
    }

    public ResponseEntity<byte[]> password(HttpServletRequest request) throws IOException {
        var response = forward(request);
        if (response.getStatusCode().value() != 200) return response;
        return signedOut(request, response);
    }

    public ResponseEntity<byte[]> updateSignIns(HttpServletRequest request) throws IOException {
        var response = forward(request);
        if (response.getStatusCode().value() != 200 || response.getBody() == null) return response;
        boolean reauthenticate;
        try {
            reauthenticate = new JsonMapper().readTree(response.getBody())
                    .path("data").path("reauthenticationRequired").asBoolean(false);
        } catch (RuntimeException invalidResponse) {
            // DLV-969: Identity said 200 but its answer is not JSON; the browser sees 503, the log says why.
            OpsLog.failed("account.identity", "IDENTITY_ANSWER_NOT_JSON").addKeyValue("upstream.service", "identity")
                    .addKeyValue("url.path", OpsLog.path(request)).addKeyValue("exception.types", OpsLog.types(invalidResponse))
                    .log("Identity's answer to {} {} was unusable: IDENTITY_ANSWER_NOT_JSON (not readable JSON: {}); answered 503", OpsLog.method(request), OpsLog.path(request),
                            OpsLog.types(invalidResponse));
            return ResponseEntity.status(503).header(HttpHeaders.CACHE_CONTROL, "no-store").build();
        }
        if (!reauthenticate) return response;
        return signedOut(request, response);
    }

    public ResponseEntity<byte[]> forward(HttpServletRequest request) throws IOException {
        var response = identity.forward(request, MAX_ACCOUNT_BYTES);
        // Infrastructure errors may contain implementation details. Identity's 4xx contract is retained.
        if (response.getStatusCode().is5xxServerError()) {
            return ResponseEntity.status(503).header(HttpHeaders.CACHE_CONTROL, "no-store")
                    .header(HttpHeaders.CONTENT_TYPE, "application/json")
                    .body("{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"The account service is temporarily unavailable. Retry shortly.\"}"
                            .getBytes(StandardCharsets.UTF_8));
        }
        return response;
    }

    /** Ends this application's session and adds the cookie that expires it in the browser to Identity's answer. */
    private ResponseEntity<byte[]> signedOut(HttpServletRequest request, ResponseEntity<byte[]> response) {
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        SecurityContextHolder.clearContext();
        var headers = new HttpHeaders();
        headers.putAll(response.getHeaders());
        headers.add(HttpHeaders.SET_COOKIE, expiredSessionCookie);
        return new ResponseEntity<>(response.getBody(), headers, response.getStatusCode());
    }
}
