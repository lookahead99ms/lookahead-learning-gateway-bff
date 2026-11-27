package com.lookahead.gateway.client;

import com.lookahead.gateway.log.RequestLog;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.NoSuchSslBundleException;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.http.client.MockClientHttpRequest;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class UpstreamHttpFactoryTest {
    static final OAuthConfigValues VALUES = new OAuthConfigValues(null, "https://dev.example.test", "synthetic-client-secret-never-deployed",
            "syntheticclient1", null, "https://domain.lookahead-dev.internal:8443", Duration.ofSeconds(3), Duration.ofSeconds(7));

    @SuppressWarnings("unchecked")
    @Test void outsideTheDevProfileTheInternalTlsBundleIsNeverRead() {
        ObjectProvider<SslBundles> bundles = mock(ObjectProvider.class);
        ObjectProvider<DevServiceOrigins> origins = mock(ObjectProvider.class);
        assertThat(UpstreamHttpFactory.from(VALUES, new MockEnvironment(), bundles, origins)).isNotNull();
        verifyNoInteractions(bundles);
        // DLV-1015: nor are the DEV origins asked for, so no start outside DEV can be refused over them.
        verifyNoInteractions(origins);
    }

    @SuppressWarnings("unchecked")
    @Test void inTheDevProfileTheConnectionIsBuiltFromTheInternalBundleAndRefusesAnInexactInternalOrigin() {
        var registry = new DefaultSslBundleRegistry();
        registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
        ObjectProvider<SslBundles> bundles = mock(ObjectProvider.class);
        when(bundles.getObject()).thenReturn(registry);
        var environment = new MockEnvironment().withProperty("app.oauth.domain-api-upstream", "https://domain.lookahead-dev.internal:8443")
                .withProperty("app.gateway.web-upstream", "https://web.lookahead-dev.internal:8443");
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        ObjectProvider<DevServiceOrigins> origins = mock(ObjectProvider.class);
        when(origins.getObject()).thenReturn(DevServiceOrigins.from(environment));
        var http = UpstreamHttpFactory.from(VALUES, environment, bundles, origins);
        verify(bundles).getObject();
        // DLV-1015: the origins are asked for once, and only after the internal bundle has been read.
        var order = inOrder(bundles, origins);
        order.verify(bundles).getObject();
        order.verify(origins).getObject();
        verifyNoMoreInteractions(origins);
        assertThatThrownBy(() -> http.get().uri(URI.create("http://domain.lookahead-dev.internal:8443/api/v1/auth/me")).retrieve().toBodilessEntity())
                .hasStackTraceContaining("Exact internal HTTPS origin required");
    }

    /** DLV-1015: the order of the two possible refusals of a DEV start is what it was: a missing internal bundle first, then a wrong upstream. */
    @SuppressWarnings("unchecked")
    @Test void inTheDevProfileAMissingInternalBundleIsReportedBeforeTheOriginsAreAskedAndARefusedOriginLeavesAsItIs() {
        var environment = new MockEnvironment();
        environment.setActiveProfiles("gateway", "lower-cost-dev");
        ObjectProvider<SslBundles> none = mock(ObjectProvider.class);
        when(none.getObject()).thenReturn(new DefaultSslBundleRegistry());
        ObjectProvider<DevServiceOrigins> origins = mock(ObjectProvider.class);
        assertThatThrownBy(() -> UpstreamHttpFactory.from(VALUES, environment, none, origins))
                .isInstanceOf(NoSuchSslBundleException.class);
        verifyNoInteractions(origins);

        var registry = new DefaultSslBundleRegistry();
        registry.registerBundle("internal", SslBundle.of(SslStoreBundle.NONE));
        ObjectProvider<SslBundles> bundles = mock(ObjectProvider.class);
        when(bundles.getObject()).thenReturn(registry);
        var refusal = new IllegalStateException("Explicit stable DEV Domain and Web upstreams required");
        when(origins.getObject()).thenThrow(refusal);
        assertThatThrownBy(() -> UpstreamHttpFactory.from(VALUES, environment, bundles, origins)).isSameAs(refusal);
    }

    /** The request ID header on outbound calls. */
    @Nested class RequestId {
    private static final String UUID_SHAPE = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

    @AfterEach void stop() {
        MDC.clear();
    }

    @Test void theIdGoesOnlyToOurOwnUpstreamsAndReplacesAnyOtherValue() throws Exception {
        var interceptor = UpstreamHttpFactory.forwardTo(uri -> uri.getHost().endsWith(".lookahead-dev.internal"));
        var sent = new ArrayList<String>();
        MDC.put(RequestLog.KEY, "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        for (String target : List.of("https://domain.lookahead-dev.internal:8443/api/v1/me", "https://auth.example.com/oauth2/token")) {
            var request = new MockClientHttpRequest(HttpMethod.GET, URI.create(target));
            request.getHeaders().add(RequestLog.HEADER, "from-the-browser");
            interceptor.intercept(request, new byte[0], (req, body) -> {
                sent.add(String.valueOf(req.getHeaders().get(RequestLog.HEADER)));
                return mock(ClientHttpResponse.class);
            });
        }
        MDC.clear();
        var outside = new MockClientHttpRequest(HttpMethod.GET, URI.create("https://domain.lookahead-dev.internal:8443/x"));
        interceptor.intercept(outside, new byte[0], (req, body) -> mock(ClientHttpResponse.class));
        assertThat(sent).containsExactly("[aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee]", "[from-the-browser]");
        assertThat(outside.getHeaders().get(RequestLog.HEADER)).isNull();
        assertThat(RequestLog.reference()).matches(UUID_SHAPE);
    }
    }
}
