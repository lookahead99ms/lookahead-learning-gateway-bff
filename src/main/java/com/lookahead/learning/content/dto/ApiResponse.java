package com.lookahead.learning.content.dto;

import java.time.Instant;

/** Gateway-owned JSON envelope; compatibility is verified at the HTTP boundary. */
public record ApiResponse<T>(T data, Instant timestamp) {

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(data, Instant.now());
    }
}
