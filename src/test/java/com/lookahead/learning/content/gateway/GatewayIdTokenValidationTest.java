package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.jwt.JwtException;
import static org.assertj.core.api.Assertions.*;

/** Real Nimbus signature/claim verification using a generated key and loopback-only JWKS. */
class GatewayIdTokenValidationTest {
    @ParameterizedTest @ValueSource(strings = {"dev", "prod"})
    void cloudIdTokenMustMatchSignatureIssuerClientAndLifetime(String mode) throws Exception {
        var settings = OAuthSettings.from(GatewayEnvironmentBindingsTest.cloudEnvironment(mode));
        var key = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
        var wrongKey = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/jwks", exchange -> {
            byte[] bytes = ("{\"keys\":[" + key.toPublicJWK().toJSONString() + "]}").getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var output = exchange.getResponseBody()) { output.write(bytes); }
        });
        server.start();
        try {
            var configuration = new GatewayClientConfiguration();
            var configured = configuration.gatewayClient(settings).findByRegistrationId("lookahead");
            // Override only transport to avoid contacting AWS. Keep each environment's
            // real configured issuer, client identity, and validator factory intact.
            var registration = ClientRegistration.withClientRegistration(configured)
                    .jwkSetUri("http://127.0.0.1:" + server.getAddress().getPort() + "/jwks").build();
            var properties = new OAuthProperties(settings.issuer(), settings.frontend(), settings.clientSecret(),
                    settings.clientId(), null, settings.domainApiUpstream(), Duration.ofSeconds(1), Duration.ofSeconds(2));
            var factory = configuration.gatewayIdTokenDecoders(properties);
            var decoder = factory.createDecoder(registration);
            var expiry = Instant.now().plusSeconds(300);
            assertThat(decoder.decode(token(key, settings.issuer(), settings.clientId(), expiry)).getSubject()).isEqualTo("synthetic-subject");
            assertThat(factory.createDecoder(registration)).isSameAs(decoder);
            assertThatThrownBy(() -> decoder.decode(token(key, "https://other-issuer.example.test", settings.clientId(), expiry))).isInstanceOf(JwtException.class);
            assertThatThrownBy(() -> decoder.decode(token(key, settings.issuer(), "other-client", expiry))).isInstanceOf(JwtException.class);
            assertThatThrownBy(() -> decoder.decode(token(key, settings.issuer(), settings.clientId(), Instant.now().minusSeconds(120)))).isInstanceOf(JwtException.class);
            assertThatThrownBy(() -> decoder.decode(token(wrongKey, settings.issuer(), settings.clientId(), expiry))).isInstanceOf(JwtException.class);
        } finally {
            server.stop(0);
        }
    }

    private static String token(RSAKey key, String issuer, String audience, Instant expiry) throws Exception {
        var claims = new JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject("synthetic-subject")
                .issueTime(Date.from(Instant.now().minusSeconds(600))).expirationTime(Date.from(expiry)).build();
        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        signed.sign(new RSASSASigner(key));
        return signed.serialize();
    }
}
