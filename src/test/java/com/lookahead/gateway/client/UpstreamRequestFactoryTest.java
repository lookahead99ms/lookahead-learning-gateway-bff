package com.lookahead.gateway.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.lookahead.gateway.util.DevServiceOrigins;
import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.JdkClientHttpRequestFactory;

/**
 * DLV-1015: which of the two connections an outbound request leaves through, driven directly. The
 * internal connection carries the client certificate, so only the two DEV upstreams get it, and
 * only at their exact HTTPS origin. The same refusal through the whole connection is in
 * UpstreamHttpFactoryTest and UpstreamHttpConfigurationTest.
 */
class UpstreamRequestFactoryTest {
  static final DevServiceOrigins ORIGINS =
      DevServiceOrigins.of(DevServiceOrigins.DOMAIN, DevServiceOrigins.WEB);
  final JdkClientHttpRequestFactory internal = mock(JdkClientHttpRequestFactory.class);
  final JdkClientHttpRequestFactory general = mock(JdkClientHttpRequestFactory.class);
  final UpstreamRequestFactory factory = new UpstreamRequestFactory(ORIGINS, internal, general);

  @Test
  void theTwoDevUpstreamsAtTheirExactHttpsOriginLeaveThroughTheInternalConnection()
      throws Exception {
    for (String target :
        List.of(
            DevServiceOrigins.DOMAIN + "/api/v1/auth/me",
            DevServiceOrigins.WEB + "/",
            DevServiceOrigins.WEB + "/assets/main.js?v=1")) {
      var uri = URI.create(target);
      var made = mock(ClientHttpRequest.class);
      when(internal.createRequest(uri, HttpMethod.GET)).thenReturn(made);
      assertThat(factory.createRequest(uri, HttpMethod.GET)).as(target).isSameAs(made);
      verify(internal).createRequest(uri, HttpMethod.GET);
    }
    verifyNoMoreInteractions(internal);
    verifyNoInteractions(general);
  }

  @Test
  void everyOtherHostLeavesThroughThePublicConnectionWhateverItsSchemeOrPort() throws Exception {
    for (String target :
        List.of(
            "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example/.well-known/jwks.json",
            "https://example.auth.us-east-2.amazoncognito.com/oauth2/token",
            "http://127.0.0.1:4315/index.html",
            "https://domain.lookahead-dev.internal.example.test:8443/api/v1/auth/me",
            "https://other.lookahead-dev.internal:8443/")) {
      var uri = URI.create(target);
      var made = mock(ClientHttpRequest.class);
      when(general.createRequest(uri, HttpMethod.POST)).thenReturn(made);
      assertThat(factory.createRequest(uri, HttpMethod.POST)).as(target).isSameAs(made);
      verify(general).createRequest(uri, HttpMethod.POST);
    }
    verifyNoMoreInteractions(general);
    verifyNoInteractions(internal);
  }

  @Test
  void aDevUpstreamOverPlainHttpOrOnAnotherPortIsRefusedBeforeEitherConnectionIsAsked() {
    for (String target :
        List.of(
            "http://domain.lookahead-dev.internal:8443/api/v1/auth/me",
            "https://domain.lookahead-dev.internal/api/v1/auth/me",
            "https://domain.lookahead-dev.internal:443/api/v1/auth/me",
            "http://web.lookahead-dev.internal/",
            "https://web.lookahead-dev.internal:8080/",
            "http://web.lookahead-dev.internal:8443/"))
      assertThatThrownBy(() -> factory.createRequest(URI.create(target), HttpMethod.GET))
          .as(target)
          .isExactlyInstanceOf(IllegalArgumentException.class)
          .hasMessage("Exact internal HTTPS origin required");
    verifyNoInteractions(internal, general);
  }
}
