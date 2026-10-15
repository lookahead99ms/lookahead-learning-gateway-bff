package com.lookahead.learning.content.oauth;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
class DevServiceOriginsTest {
    @Test void selectedSlotDoesNotAuthorizeOtherSlotOrPublicProvider() {
        for(String slot:new String[]{"blue","green"}) {
            var origins=DevServiceOrigins.forSlot(slot);
            assertTrue(origins.internal(java.net.URI.create(origins.web())));
            assertTrue(origins.internal(java.net.URI.create(origins.domain())));
            String other=slot.equals("blue")?"green":"blue";
            assertFalse(origins.internal(java.net.URI.create("https://web-"+other+".lookahead-dev.internal:8443")));
            assertFalse(origins.internal(java.net.URI.create("https://cognito-idp.us-east-2.amazonaws.com")));
        }
    }
    @Test void noImplicitSlotOrArbitraryHostname() {
        for(String invalid:new String[]{"", "BLUE", "blue.evil.example", "blue/../green"})
            assertThrows(IllegalStateException.class,()->DevServiceOrigins.forSlot(invalid));
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.forSlot(null));
    }
}
