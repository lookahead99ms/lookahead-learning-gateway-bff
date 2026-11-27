package com.lookahead.gateway.security.handler;
import jakarta.servlet.http.*;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.http.ResponseEntity;
import java.util.Map;
import java.io.IOException;

/**
 * What the DEV gate's own routes answer: the gate page (with the Google button only while Google sign-in is switched on,
 * decided once when this handler is built), the CSRF token for the Leave DEV button, leaving DEV and its completion.
 * The sign-out behind leaving DEV is {@link SignOutHandler#leaveDev}. The routes are in {@code DevAccessController}.
 */
public final class DevAccessHandler {
    private final boolean google;
    private final SignOutHandler signOut;
    public DevAccessHandler(boolean google, SignOutHandler signOut) { this.google = google; this.signOut = signOut; }
    private static final DevAccessPage PAGE = DevAccessPage.load(DevAccessPage.RESOURCE);
    /** The gate page ({@code GET /dev/access}) with the notice the two parameters select; never stored, and its policy admits exactly its own style block. */
    public ResponseEntity<String> access(String access, String error) {
        String body = PAGE.render(google, DevAccessPage.Notice.from(access, error));
        return ResponseEntity.ok().header("Cache-Control", "no-store").header("Content-Security-Policy", PAGE.policy).body(body);
    }
    /** The CSRF token of the gate's own chain ({@code GET /dev/csrf}), under the header name the Web shell sends it back in. */
    public ResponseEntity<Map<String,String>> csrf(CsrfToken token) {
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(Map.of("headerName", token.getHeaderName(), "token", token.getToken()));
    }
    /** Leaving DEV ({@code POST /dev/leave}): the sign-out, then where the browser goes next and whether the platform sign-out was confirmed. */
    public ResponseEntity<Map<String,String>> leave(HttpServletRequest request, HttpServletResponse response) {
        boolean learnerConfirmed = signOut.leaveDev(request, response);
        String target = signOut.leaveDevUrl();
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(Map.of("logoutUrl", target,
            "learnerSignOutConfirmed", Boolean.toString(learnerConfirmed), "providerRevocationConfirmed", "false"));
    }
    /** After the provider's logout page ({@code GET /dev/leave/complete}): back to the gate page. */
    public void complete(HttpServletResponse response) throws IOException {
        response.setHeader("Cache-Control", "no-store");
        response.sendRedirect("/dev/access");
    }
}
