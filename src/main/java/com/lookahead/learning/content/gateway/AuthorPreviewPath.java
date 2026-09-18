package com.lookahead.learning.content.gateway;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

final class AuthorPreviewPath {
    static final String PREFIX = "/bff/author/previews/";

    private AuthorPreviewPath() { }

    static URI target(URI upstream, String path, String query) {
        if (path == null || !path.startsWith(PREFIX) || path.length() > 2048) {
            throw new IllegalArgumentException("Invalid preview path");
        }
        String relative = path.substring(PREFIX.length());
        // Encoded separators, percent signs and dot segments cannot acquire another meaning downstream.
        for (String segment : relative.split("/", -1)) {
            String decoded = URLDecoder.decode(segment.replace("+", "%2B"), StandardCharsets.UTF_8);
            if (decoded.equals(".") || decoded.equals("..")
                    || !decoded.matches("[A-Za-z0-9_. +@()-]*")) {
                throw new IllegalArgumentException("Invalid preview path");
            }
        }
        if (relative.startsWith("/") || relative.contains("//") || relative.contains("\\")
                || path.chars().anyMatch(value -> value <= 32 || value >= 127)) {
            throw new IllegalArgumentException("Invalid preview path");
        }
        if (query != null && (query.length() > 4096 || query.contains("#") || query.contains("\\")
                || query.chars().anyMatch(value -> value <= 32 || value >= 127)
                || URLDecoder.decode(query, StandardCharsets.UTF_8).chars().anyMatch(value -> value < 32 || value == 127))) {
            throw new IllegalArgumentException("Invalid preview query");
        }
        URI target = URI.create(upstream + "/" + relative + (query == null ? "" : "?" + query));
        if (!upstream.getRawAuthority().equals(target.getRawAuthority())) {
            throw new IllegalArgumentException("Invalid preview target");
        }
        return target;
    }
}
