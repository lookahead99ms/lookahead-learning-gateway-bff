package com.lookahead.gateway.dto;

import java.time.Instant;

/** JSON envelope owned by the Gateway BFF; compatibility is verified at the HTTP boundary. */
public record ApiResponse<T>(T data, Instant timestamp) {

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(data, Instant.now());
    }
}
