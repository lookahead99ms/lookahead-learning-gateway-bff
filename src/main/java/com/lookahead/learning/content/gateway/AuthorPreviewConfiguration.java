package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthProperties;
import com.lookahead.learning.content.oauth.OAuthSettings;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import java.io.IOException;
import java.net.HttpURLConnection;

@Configuration
@Profile("gateway")
@ConditionalOnProperty(name = "app.author-previews.enabled", havingValue = "true")
class AuthorPreviewConfiguration {
    @Bean AuthorPreviewSettings authorPreviewSettings(Environment environment, OAuthSettings oauth) {
        return AuthorPreviewSettings.from(environment, oauth);
    }

    @Bean AuthorPreviewProxy authorPreviewProxy(AuthorPreviewSettings settings, OAuthSettings oauth, OAuthProperties properties) {
        var requests = new SimpleClientHttpRequestFactory() {
            @Override protected void prepareConnection(HttpURLConnection connection, String method) throws IOException {
                super.prepareConnection(connection, method);
                connection.setInstanceFollowRedirects(false);
            }
        };
        requests.setConnectTimeout(properties.connectTimeout());
        requests.setReadTimeout(properties.readTimeout());
        return new AuthorPreviewProxy(settings, oauth, RestClient.builder().requestFactory(requests).build());
    }
}
