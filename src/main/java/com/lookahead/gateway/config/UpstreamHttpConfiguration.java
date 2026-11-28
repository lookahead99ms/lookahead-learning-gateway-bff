package com.lookahead.gateway.config;

import com.lookahead.gateway.client.UpstreamHttpFactory;
import com.lookahead.gateway.security.oauth.OAuthConfigValues;
import com.lookahead.gateway.util.DevServiceOrigins;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.context.annotation.*;
import org.springframework.core.env.Environment;
import org.springframework.web.client.RestClient;

/**
 * The one general HTTP connection to our own upstreams (bean {@code upstreamHttp}) and, in DEV, the
 * two upstream origins it may use.
 */
@Configuration
@Profile("gateway")
public class UpstreamHttpConfiguration {
  /**
   * The {@code lower-cost-dev} profile only: the two private DEV upstreams, read and checked once;
   * a wrong one refuses the start. Lazy on purpose: it is created when the connection below asks
   * for it, which is after the connection has read the internal TLS bundle, so a start with both
   * wrong is refused for the same reason as before. {@code DevWebProxy} receives it too.
   */
  @Bean
  @Lazy
  @Profile("lower-cost-dev")
  DevServiceOrigins devServiceOrigins(Environment environment) {
    return DevServiceOrigins.from(environment);
  }

  @Bean
  public RestClient upstreamHttp(
      OAuthConfigValues values,
      Environment environment,
      ObjectProvider<SslBundles> bundles,
      ObjectProvider<DevServiceOrigins> devOrigins) {
    return UpstreamHttpFactory.from(values, environment, bundles, devOrigins);
  }
}
