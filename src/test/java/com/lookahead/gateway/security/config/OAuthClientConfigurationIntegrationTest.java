package com.lookahead.gateway.security.config;

import static org.assertj.core.api.Assertions.*;

import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
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

/** Real Nimbus signature/claim verification using a generated key and loopback-only JWKS. */
class OAuthClientConfigurationIntegrationTest {
  @ParameterizedTest
  @ValueSource(strings = {"dev", "prod"})
  void cloudIdTokenMustMatchSignatureIssuerClientAndLifetime(String mode) throws Exception {
    var oauth =
        OAuthClientDetailsFactory.from(OAuthClientDetailsFactoryTest.cloudEnvironment(mode));
    var key = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
    var wrongKey = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
    var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/jwks",
        exchange -> {
          byte[] bytes =
              ("{\"keys\":[" + key.toPublicJWK().toJSONString() + "]}")
                  .getBytes(StandardCharsets.UTF_8);
          exchange.getResponseHeaders().set("Content-Type", "application/json");
          exchange.sendResponseHeaders(200, bytes.length);
          try (var output = exchange.getResponseBody()) {
            output.write(bytes);
          }
        });
    server.start();
    try {
      var configuration = new OAuthClientConfiguration();
      var configured =
          configuration.oauthClientRegistrations(oauth).findByRegistrationId("lookahead");
      // Override only transport to avoid contacting AWS. Keep each environment's
      // real configured issuer, client identity, and validator factory intact.
      var registration =
          ClientRegistration.withClientRegistration(configured)
              .jwkSetUri("http://127.0.0.1:" + server.getAddress().getPort() + "/jwks")
              .build();
      var values =
          new OAuthConfigValues(
              oauth.issuer(),
              oauth.frontend(),
              oauth.clientSecret(),
              oauth.clientId(),
              null,
              oauth.domainApiUpstream(),
              Duration.ofSeconds(1),
              Duration.ofSeconds(2));
      var factory = configuration.oauthIdTokenDecoders(values);
      var decoder = factory.createDecoder(registration);
      var expiry = Instant.now().plusSeconds(300);
      assertThat(decoder.decode(token(key, oauth.issuer(), oauth.clientId(), expiry)).getSubject())
          .isEqualTo("synthetic-subject");
      assertThat(factory.createDecoder(registration)).isSameAs(decoder);
      assertThatThrownBy(() ->
              decoder.decode(
                  token(key, "https://other-issuer.example.test", oauth.clientId(), expiry)))
          .isInstanceOf(JwtException.class);
      assertThatThrownBy(() -> decoder.decode(token(key, oauth.issuer(), "other-client", expiry)))
          .isInstanceOf(JwtException.class);
      assertThatThrownBy(() ->
              decoder.decode(
                  token(key, oauth.issuer(), oauth.clientId(), Instant.now().minusSeconds(120))))
          .isInstanceOf(JwtException.class);
      assertThatThrownBy(
              () -> decoder.decode(token(wrongKey, oauth.issuer(), oauth.clientId(), expiry)))
          .isInstanceOf(JwtException.class);
    } finally {
      server.stop(0);
    }
  }

  private static String token(RSAKey key, String issuer, String audience, Instant expiry)
      throws Exception {
    var claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience(audience)
            .subject("synthetic-subject")
            .issueTime(Date.from(Instant.now().minusSeconds(600)))
            .expirationTime(Date.from(expiry))
            .build();
    var signed =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
    signed.sign(new RSASSASigner(key));
    return signed.serialize();
  }
}
