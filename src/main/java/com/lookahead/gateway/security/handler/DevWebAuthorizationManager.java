package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.proxy.DevWebProxy;
import java.util.Set;
import java.util.function.Supplier;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;

/**
 * The last rule of the sign-in chain, for a request no earlier rule matched: allowed only under the
 * {@code lower-cost-dev} profile, only for GET and HEAD, and only for a path the Web fallback may
 * serve ({@link DevWebProxy#safePath}). Everywhere else, and for everything else, the answer is no.
 */
public final class DevWebAuthorizationManager
    implements AuthorizationManager<RequestAuthorizationContext> {
  private final Environment environment;

  public DevWebAuthorizationManager(Environment environment) {
    this.environment = environment;
  }

  @Override
  public AuthorizationResult authorize(
      Supplier<? extends Authentication> authentication, RequestAuthorizationContext context) {
    return new AuthorizationDecision(
        environment.acceptsProfiles(Profiles.of("lower-cost-dev"))
            && Set.of("GET", "HEAD").contains(context.getRequest().getMethod())
            && DevWebProxy.safePath(context.getRequest().getRequestURI()));
  }
}
