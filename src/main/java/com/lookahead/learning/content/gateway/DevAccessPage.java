package com.lookahead.learning.content.gateway;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/** The DEV admission gate page: one self-contained classpath document and the policy that admits exactly its inline style block. */
final class DevAccessPage {
    static final String RESOURCE = "dev-access.html";
    static final String BASE_POLICY = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
    final String html;
    final String policy;
    DevAccessPage(String html) {
        this.html = html;
        this.policy = BASE_POLICY + "; style-src 'sha256-" + styleHash(html) + "'";
    }
    static DevAccessPage load(String resource) {
        try (InputStream in = DevAccessPage.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) throw new IllegalStateException("Missing classpath resource " + resource);
            return new DevAccessPage(new String(in.readAllBytes(), StandardCharsets.UTF_8));
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }
    /** Base64 SHA-256 of the exact text between the page's single {@code <style>} and {@code </style>}, as CSP hashes it. */
    static String styleHash(String html) {
        int start = html.indexOf("<style>"), end = html.indexOf("</style>", start);
        if (start < 0 || end < 0 || html.indexOf("<style", end) >= 0) throw new IllegalStateException("The page must carry exactly one <style> block");
        byte[] css = html.substring(start + "<style>".length(), end).getBytes(StandardCharsets.UTF_8);
        try {
            return Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(css));
        } catch (NoSuchAlgorithmException missing) {
            throw new IllegalStateException(missing);
        }
    }
}
