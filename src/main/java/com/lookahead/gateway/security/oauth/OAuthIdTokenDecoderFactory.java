package com.lookahead.gateway.security.oauth;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.web.client.RestOperations;

/**
 * Builds, once per client registration, the decoder that checks an ID token's signature, issuer,
 * audience and lifetime.
 *
 * <p>Exception, decided 2026-11-25 (DLV-1015): this class builds Spring Security's ID-token
 * decoder, which fetches the provider's signing keys itself over the transport this class receives
 * ready-made (rule 4: only a client class talks to an outside system). Spring Security asks for the
 * decoder per client registration through {@code JwtDecoderFactory}, so that call is made by
 * Spring's class and not by a client class of ours.
 */
public final class OAuthIdTokenDecoderFactory implements JwtDecoderFactory<ClientRegistration> {
  private final ConcurrentHashMap<String, JwtDecoder> decoders =
      new ConcurrentHashMap<String, JwtDecoder>();
  private final RestOperations keyHttp;

  public OAuthIdTokenDecoderFactory(RestOperations keyHttp) {
    this.keyHttp = keyHttp;
  }

  @Override
  public JwtDecoder createDecoder(ClientRegistration registration) {
    return decoders.computeIfAbsent(
        registration.getRegistrationId(),
        key -> {
          var decoder =
              NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                  .restOperations(keyHttp)
                  .build();
          decoder.setJwtValidator(
              new DelegatingOAuth2TokenValidator<>(
                  new JwtTimestampValidator(), new OidcIdTokenValidator(registration)));
          return decoder;
        });
  }
}
