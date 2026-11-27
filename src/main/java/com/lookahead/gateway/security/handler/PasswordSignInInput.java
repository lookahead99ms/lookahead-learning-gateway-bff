package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.util.PasswordSignInAnswer;
import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.Locale;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** DLV-969: what the password sign-in routes read from a request: the body, its validated fields and the caller's address. */
public final class PasswordSignInInput {
    private PasswordSignInInput() {}

    static final int MAX_BODY = 8192;
    private static final JsonMapper json = new JsonMapper();

    /** What {@link #read} found: the fields of the JSON object, or the refusal when the body was too large or not a JSON object. */
    public record Body(JsonNode fields, ResponseEntity<?> refusal) {}

    /** Reads the body of one page request, at most {@link #MAX_BODY} bytes. */
    public static Body read(HttpServletRequest request) {
        JsonNode body;
        try {
            byte[] raw = request.getInputStream().readNBytes(MAX_BODY + 1);
            if (raw.length > MAX_BODY) return new Body(null, PasswordSignInAnswer.failure(413, "REQUEST_TOO_LARGE"));
            body = json.readTree(raw);
            if (body == null || !body.isObject()) return new Body(null, PasswordSignInAnswer.failure(400, "INVALID_REQUEST"));
        } catch (IOException | RuntimeException unreadable) {
            return new Body(null, PasswordSignInAnswer.failure(400, "INVALID_REQUEST"));
        }
        return new Body(body, null);
    }

    // ----- input rules: bounded, no control characters; secrets are never echoed back -----

    public static String text(JsonNode body, String field, int max, boolean optional) {
        JsonNode node = body.get(field);
        if (node == null || node.isNull()) { if (optional) return null; throw new IllegalArgumentException(field); }
        if (!node.isString()) throw new IllegalArgumentException(field);
        String value = node.asString();
        if (value.length() > max || value.codePoints().anyMatch(Character::isISOControl)) throw new IllegalArgumentException(field);
        return value;
    }
    public static String email(JsonNode body) {
        String value = text(body, "email", 254, false).strip();
        if (!value.matches("[^@\\s]{1,64}@[^@\\s]{1,189}\\.[^@\\s]{1,63}")) throw new IllegalArgumentException("email");
        return value.toLowerCase(Locale.ROOT);
    }
    public static String secret(JsonNode body, String field) {
        String value = text(body, field, 256, false);
        if (value.isEmpty()) throw new IllegalArgumentException(field);
        return value;
    }
    public static String code(JsonNode body) {
        String value = text(body, "code", 16, false).strip();
        if (!value.matches("[0-9]{6,8}")) throw new IllegalArgumentException("code");
        return value;
    }
    public static String name(JsonNode body, String field) {
        String value = text(body, field, 80, false).strip();
        if (value.isEmpty()) throw new IllegalArgumentException(field);
        return value;
    }
    /**
     * The address the request reached the Gateway BFF from: the last X-Forwarded-For hop when present (added by the
     * load balancer).
     */
    public static String address(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            String[] hops = forwarded.split(",");
            String last = hops[hops.length - 1].strip();
            if (!last.isEmpty() && last.length() <= 64) return last;
        }
        return request.getRemoteAddr();
    }
}
