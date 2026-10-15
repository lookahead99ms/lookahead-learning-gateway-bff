package com.lookahead.learning.content.oauth;

/** Fixed private origins keep a release candidate out of the active slot's discovery. */
public record DevServiceOrigins(String domain, String web) {
    public static DevServiceOrigins forSlot(String slot) {
        if (!java.util.Set.of("blue", "green").contains(slot == null ? "" : slot))
            throw new IllegalStateException("Explicit blue or green DEV release slot required");
        return new DevServiceOrigins("https://domain-" + slot + ".lookahead-dev.internal:8443",
                "https://web-" + slot + ".lookahead-dev.internal:8443");
    }
    public boolean internal(java.net.URI uri) {
        return java.util.Set.of(java.net.URI.create(domain).getHost(), java.net.URI.create(web).getHost()).contains(uri.getHost());
    }
}
