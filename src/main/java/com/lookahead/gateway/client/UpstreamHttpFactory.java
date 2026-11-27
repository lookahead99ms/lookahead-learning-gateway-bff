package com.lookahead.gateway.client;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.log.RequestLog;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.DevServiceOrigins;
import java.net.URI;
import java.net.http.HttpClient;
import java.util.function.Predicate;
import org.slf4j.MDC;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * Builds the one general HTTP connection to our own upstreams: the plain one, or in DEV the one that also holds the internal client certificate.
 * It puts the outbound call together (the connection, the request ID header and the upstream log line), which is why it lives in {@code client}.
 */
public final class UpstreamHttpFactory {
    private UpstreamHttpFactory() {}

    public static JdkClientHttpRequestFactory boundedRequests(OAuthConfigValues values) {
        // HttpURLConnection's streaming POST handling can discard a 401 response body.
        // Preserve Identity's structured credential errors without following redirects.
        var client = HttpClient.newBuilder()
                .connectTimeout(values.connectTimeout())
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        var factory = new JdkClientHttpRequestFactory(client);
        factory.setReadTimeout(values.readTimeout());
        return factory;
    }

    public static RestClient from(OAuthConfigValues values, Environment environment,
            ObjectProvider<SslBundles> bundles,
            ObjectProvider<DevServiceOrigins> devOrigins) {
        var publicRequests = boundedRequests(values);
        // DLV-969: the request ID goes to our own upstreams so their log lines match this request's, and every call
        // writes one lookahead.upstream line (service, method, path, status, time; never headers, bodies or the query).
        var services = OpsLog.services(environment);
        if (!environment.acceptsProfiles(Profiles.of("lower-cost-dev")))
            return RestClient.builder().requestFactory(publicRequests).requestInterceptor(forwardTo(uri -> true))
                    .requestInterceptor(OpsLog.upstream(services)).build();
        var client = HttpClient.newBuilder().connectTimeout(values.connectTimeout())
                .sslContext(bundles.getObject().getBundle("internal").createSslContext())
                .followRedirects(HttpClient.Redirect.NEVER).build();
        var internalRequests = new JdkClientHttpRequestFactory(client);
        internalRequests.setReadTimeout(values.readTimeout());
        var origins = devOrigins.getObject();
        // Never send the internal client certificate to Cognito, any host other than the two configured
        // upstreams, or other public providers; the TLS layer then verifies the upstream leaf's name.
        return RestClient.builder().requestFactory(new UpstreamRequestFactory(origins, internalRequests, publicRequests))
                .requestInterceptor(forwardTo(origins::internal)).requestInterceptor(OpsLog.upstream(services)).build();
    }

    /** Passes the request ID on to the upstreams {@code upstream} accepts, replacing anything the browser sent. */
    static ClientHttpRequestInterceptor forwardTo(Predicate<URI> upstream) {
        return (request, body, execution) -> {
            String id = MDC.get(RequestLog.KEY);
            if (id != null && upstream.test(request.getURI())) request.getHeaders().set(RequestLog.HEADER, id);
            return execution.execute(request, body);
        };
    }
}
