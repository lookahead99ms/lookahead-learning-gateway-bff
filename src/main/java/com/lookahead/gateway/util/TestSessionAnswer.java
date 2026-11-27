package com.lookahead.gateway.util;

import java.nio.charset.StandardCharsets;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/** DLV-969 S35: the browser answers of the DEV test-session routes: a JSON body that is never stored, and a refusal with its code and message. */
public final class TestSessionAnswer {
    private TestSessionAnswer() {}

    public static ResponseEntity<byte[]> failure(int status, String code, String message) {
        return json(status, ("{\"code\":\"" + code + "\",\"message\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    public static ResponseEntity<byte[]> json(int status, byte[] body) {
        return ResponseEntity.status(status).header(HttpHeaders.CACHE_CONTROL, "no-store").contentType(MediaType.APPLICATION_JSON).body(body);
    }
}
