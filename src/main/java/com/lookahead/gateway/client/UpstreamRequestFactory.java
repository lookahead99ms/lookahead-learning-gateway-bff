package com.lookahead.gateway.client;

import com.lookahead.gateway.util.DevServiceOrigins;
import java.io.IOException;
import java.net.URI;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.JdkClientHttpRequestFactory;

/**
 * Chooses the internal (client certificate) or the public connection for each upstream request.
 * It is the connection step of every outbound call to our own upstreams, which is why it lives in {@code client}.
 */
public final class UpstreamRequestFactory implements ClientHttpRequestFactory {
    private final DevServiceOrigins origins;
    private final JdkClientHttpRequestFactory internalRequests;
    private final JdkClientHttpRequestFactory publicRequests;

    public UpstreamRequestFactory(DevServiceOrigins origins, JdkClientHttpRequestFactory internalRequests, JdkClientHttpRequestFactory publicRequests) {
        this.origins = origins;
        this.internalRequests = internalRequests;
        this.publicRequests = publicRequests;
    }

    @Override public ClientHttpRequest createRequest(URI uri, HttpMethod method) throws IOException {
        boolean internal = origins.internal(uri);
        if (internal && (!"https".equals(uri.getScheme()) || uri.getPort() != 8443))
            throw new IllegalArgumentException("Exact internal HTTPS origin required");
        return (internal ? internalRequests : publicRequests).createRequest(uri, method);
    }
}
