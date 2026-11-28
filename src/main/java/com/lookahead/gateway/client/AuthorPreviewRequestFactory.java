package com.lookahead.gateway.client;

import java.io.IOException;
import java.net.HttpURLConnection;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

/**
 * The connection factory for the author-preview upstream: redirects are never followed. It is the
 * connection step of the outbound call to the preview upstream, which is why it lives in {@code
 * client}.
 */
public class AuthorPreviewRequestFactory extends SimpleClientHttpRequestFactory {
  @Override
  protected void prepareConnection(HttpURLConnection connection, String method) throws IOException {
    super.prepareConnection(connection, method);
    connection.setInstanceFollowRedirects(false);
  }
}
