package com.lookahead.gateway.client;

/** DLV-969: the DEV gate's question about one user of the sign-in pool. */
@FunctionalInterface public interface DevAccessClient {
    /**
     * True while the user still exists and is enabled in the sign-in pool; false once the owner disabled or deleted
     * them. Throws when the pool cannot answer, and the session then continues until the next request asks again.
     */
    boolean allowed(String username);
}
