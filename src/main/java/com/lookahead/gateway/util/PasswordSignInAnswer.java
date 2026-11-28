package com.lookahead.gateway.util;

import com.lookahead.gateway.dto.ApiResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.ResponseEntity;

/**
 * The answers of the password sign-in routes: the next step for the page, a refusal code, and where
 * a code was sent.
 */
public final class PasswordSignInAnswer {
  private PasswordSignInAnswer() {}

  public static ResponseEntity<?> step(String kind, String destination) {
    return step(kind, destination, null, false);
  }

  public static ResponseEntity<?> step(
      String kind, String destination, String next, boolean mergeAvailable) {
    var data = new LinkedHashMap<String, Object>();
    data.put("step", kind);
    if (destination != null) data.put("destination", destination);
    if (next != null) data.put("next", next);
    if (mergeAvailable) data.put("mergeAvailable", true);
    return ResponseEntity.ok().header("Cache-Control", "no-store").body(ApiResponse.success(data));
  }

  public static ResponseEntity<?> failure(int status, String code) {
    return ResponseEntity.status(status)
        .header("Cache-Control", "no-store")
        .body(Map.of("code", code));
  }

  /**
   * Where the code went: the address Cognito named, else the email with all but its first letter
   * and domain hidden.
   */
  public static String destination(String destination, String email) {
    return destination != null && !destination.isBlank() ? destination : masked(email);
  }

  public static String masked(String email) {
    int at = email.indexOf('@');
    return at <= 0 ? "your email" : email.charAt(0) + "***" + email.substring(at);
  }
}
