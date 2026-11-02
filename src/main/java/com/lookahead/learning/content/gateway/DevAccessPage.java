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
    /** A short server-chosen message above the buttons; the page carries no script, so the server picks it (DLV-969). */
    enum Notice {
        NONE(""),
        PENDING("Your sign-in worked. The owner has to approve your access before DEV opens. Sign in again once you hear back."),
        FAILED("That sign-in did not complete. Try again.");
        final String text;
        Notice(String text) { this.text = text; }
        static Notice from(String access, String error) {
            if ("pending".equals(access)) return PENDING;
            return error == null ? NONE : FAILED;
        }
    }
    static final String NOTICE_MARK = "<!--notice-->", GOOGLE_START = "<!--google-->", GOOGLE_END = "<!--/google-->";
    /** The served page: the Google button only while the pool has Google; the notice from fixed text only, never request input. */
    String render(boolean google, Notice notice) {
        int start = html.indexOf(GOOGLE_START), end = html.indexOf(GOOGLE_END);
        if (start < 0 || end < start || html.indexOf(NOTICE_MARK) < 0) throw new IllegalStateException("The page must carry the notice and Google marks");
        String page = google ? html.replace(GOOGLE_START, "").replace(GOOGLE_END, "")
            : html.substring(0, start) + html.substring(end + GOOGLE_END.length());
        return page.replace(NOTICE_MARK, notice == Notice.NONE ? "" : "<p class=\"notice\" role=\"status\">" + notice.text + "</p>");
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
