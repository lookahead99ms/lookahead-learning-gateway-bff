package com.lookahead.gateway.security.oauth;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/** DLV-1015: the region parse was written three times (two Cognito clients and the factory); its tests moved here with it. */
class OAuthClientDetailsTest {
    @Test void theRegionIsTheOneNamedInTheIssuersHost() {
        assertEquals("us-east-2", OAuthClientDetails.region(oauth("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example").issuer()));
        assertEquals("us-west-2", OAuthClientDetails.region(oauth("https://cognito-idp.us-west-2.amazonaws.com/us-west-2_Example").issuer()));
    }
    @Test void anIssuerWithoutARegionInItsHostIsRefused() {
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> OAuthClientDetails.region(oauth("https://localhost/pool").issuer()));
    }
    private static OAuthClientDetails oauth(String issuer) {
        return new OAuthClientDetails(issuer, "client", "synthetic-secret", "http://identity", "http://domain", "https://dev.example");
    }
}
