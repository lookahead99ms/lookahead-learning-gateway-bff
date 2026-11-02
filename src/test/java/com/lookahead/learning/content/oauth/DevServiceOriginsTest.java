package com.lookahead.learning.content.oauth;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;
import static org.junit.jupiter.api.Assertions.*;
class DevServiceOriginsTest {
    @Test void stableNamesAreTheOnlyInternalDestinations() {
        var origins=DevServiceOrigins.of(DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB);
        assertEquals("https://domain.lookahead-dev.internal:8443", origins.domain());
        assertEquals("https://web.lookahead-dev.internal:8443", origins.web());
        assertTrue(origins.internal(URI.create(origins.web()+"/learn")));
        assertTrue(origins.internal(URI.create(origins.domain()+"/api/v1/auth/me")));
        for(String external:List.of("https://cognito-idp.us-east-2.amazonaws.com","https://web-blue.lookahead-dev.internal:8443",
                "https://domain-green.lookahead-dev.internal:8443","https://domain.lookahead-dev.internal.attacker.test:8443","https://gateway.lookahead-dev.internal:8443"))
            assertFalse(origins.internal(URI.create(external)), external);
    }
    @Test void configuredEnvironmentValuesSelectTheUpstreams() {
        var environment=new MockEnvironment().withProperty(DevServiceOrigins.DOMAIN_PROPERTY, DevServiceOrigins.DOMAIN)
                .withProperty(DevServiceOrigins.WEB_PROPERTY, DevServiceOrigins.WEB);
        assertEquals(new DevServiceOrigins(DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB), DevServiceOrigins.from(environment));
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.from(new MockEnvironment().withProperty(DevServiceOrigins.DOMAIN_PROPERTY, DevServiceOrigins.DOMAIN)));
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.from(new MockEnvironment().withProperty(DevServiceOrigins.WEB_PROPERTY, DevServiceOrigins.WEB)));
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.from(new MockEnvironment()));
    }
    @Test void slotNamesStayAcceptedOnlyUntilSlotTeardown() {
        // DLV-968 S3, 2026-11-01: transitional; S5 removes the slot names and this test with them.
        for(String slot:List.of("blue","green")) {
            var origins=DevServiceOrigins.of("https://domain-"+slot+".lookahead-dev.internal:8443","https://web-"+slot+".lookahead-dev.internal:8443");
            assertTrue(origins.internal(URI.create(origins.domain())));
            assertFalse(origins.internal(URI.create(DevServiceOrigins.DOMAIN)));
        }
        // A slot Domain with the stable Web is a valid mixed transition; nothing else is.
        assertNotNull(DevServiceOrigins.of("https://domain-blue.lookahead-dev.internal:8443", DevServiceOrigins.WEB));
    }
    @Test void noImplicitUpstreamArbitraryHostnameOrSwappedRole() {
        for(String invalid:List.of("", "https://domain.lookahead-dev.internal:8081", "https://domain.lookahead-dev.internal",
                "http://domain.lookahead-dev.internal:8443", "https://domain.lookahead-dev.internal:8443/", "https://DOMAIN.lookahead-dev.internal:8443",
                "https://domain.attacker.test:8443", "https://domain.lookahead-dev.internal.attacker.test:8443", "https://domain-red.lookahead-dev.internal:8443",
                "https://web.lookahead-dev.internal:8443", "http://domain:8080"))
            assertThrows(IllegalStateException.class,()->DevServiceOrigins.of(invalid, DevServiceOrigins.WEB), invalid);
        for(String invalid:List.of("", "https://web.lookahead-dev.internal:8081", "http://web.lookahead-dev.internal:8443",
                "https://web.lookahead-dev.internal:8443/index.html", "https://domain.lookahead-dev.internal:8443", "https://web.attacker.test:8443"))
            assertThrows(IllegalStateException.class,()->DevServiceOrigins.of(DevServiceOrigins.DOMAIN, invalid), invalid);
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.of(null, DevServiceOrigins.WEB));
        assertThrows(IllegalStateException.class,()->DevServiceOrigins.of(DevServiceOrigins.DOMAIN, null));
    }
}
