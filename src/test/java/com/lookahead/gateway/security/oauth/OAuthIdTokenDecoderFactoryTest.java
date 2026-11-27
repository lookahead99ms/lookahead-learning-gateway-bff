package com.lookahead.gateway.security.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.web.client.RestOperations;

/** DLV-1015: the factory builds no transport; Spring's decoder fetches the signing keys over the one it was given. */
class OAuthIdTokenDecoderFactoryTest {
    @Test void theDecoderFetchesTheSigningKeysOverTheGivenTransportAndIsBuiltOncePerRegistration() throws Exception {
        var oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
        ClientRegistration registration = OAuthClientRegistrationFactory.from(oauth);
        var key = new RSAKeyGenerator(2048).keyID("fixture-key").generate();
        RestOperations transport = mock(RestOperations.class);
        when(transport.exchange(any(RequestEntity.class), eq(String.class)))
            .thenReturn(ResponseEntity.ok("{\"keys\":[" + key.toPublicJWK().toJSONString() + "]}"));
        var factory = new OAuthIdTokenDecoderFactory(transport);

        var decoder = factory.createDecoder(registration);
        assertThat(factory.createDecoder(registration)).isSameAs(decoder);
        verifyNoInteractions(transport);   // nothing is fetched until a token is decoded

        var claims = new JWTClaimsSet.Builder().issuer(oauth.issuer()).audience(oauth.clientId()).subject("synthetic-subject")
            .issueTime(Date.from(Instant.now().minusSeconds(60))).expirationTime(Date.from(Instant.now().plusSeconds(300))).build();
        var signed = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims);
        signed.sign(new RSASSASigner(key));
        assertThat(decoder.decode(signed.serialize()).getSubject()).isEqualTo("synthetic-subject");

        var request = ArgumentCaptor.forClass(RequestEntity.class);
        verify(transport).exchange(request.capture(), eq(String.class));
        assertThat(request.getValue().getUrl().toString()).isEqualTo(registration.getProviderDetails().getJwkSetUri());
    }
}
