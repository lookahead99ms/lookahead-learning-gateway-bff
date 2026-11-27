package com.lookahead.gateway.security.filter;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.DevAccessSession;
import com.lookahead.gateway.security.session.SignInCheckSession;
import com.lookahead.gateway.security.session.SignInProofSession;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Domain verification protects every private BFF request. DLV-969 S37 (user, 2026-11-03): reads of {@code /bff/api/v1/**}
 * (GET or HEAD), which the Domain verifies again on the real call, reuse a passed check for {@link SignInCheckSession#REUSE} within this
 * session and for the same person. Writes, the CSRF token and staff previews ({@code /bff/author/previews/**}) are
 * still checked on every request, so a revoked sign-in can neither write nor fetch a CSRF token.
 */
public final class SignInCheckFilter extends OncePerRequestFilter {
    private final SignInTokenClient tokens;
    private final SignInDomainClient domainClient;
    private final OAuthClientDetails oauth;
    private final SignInCheckSession checks;

    public SignInCheckFilter(SignInTokenClient tokens, SignInDomainClient domainClient, OAuthClientDetails oauth) {
        this(tokens, domainClient, oauth, Clock.systemUTC());
    }
    SignInCheckFilter(SignInTokenClient tokens, SignInDomainClient domainClient, OAuthClientDetails oauth, Clock clock) {
        this.tokens = tokens;
        this.domainClient = domainClient;
        this.oauth = oauth;
        this.checks = new SignInCheckSession(clock);
    }

    @Override public boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !(path.startsWith("/bff/api/v1/") || path.startsWith("/bff/author/previews/")
                || oauth.cloud() && SignInProofSession.restricted(request) && path.startsWith("/content/"))
                || path.equals("/bff/api/v1/auth/logout")
                // DLV-969: our password page starts a new sign-in; like /bff/login it must work from any prior state.
                || path.startsWith("/bff/api/v1/auth/password/");
    }

    @Override protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain chain) throws ServletException, IOException {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        if (oauth.cloud() && SignInProofSession.restricted(request)) {
            if (request.getRequestURI().equals("/bff/api/v1/auth/csrf")) {
                chain.doFilter(request, response);
                return;
            }
            OpsLog.refused("sign-in.check", "SIGN_IN_CHALLENGE_REQUIRED").addKeyValue("url.path", OpsLog.path(request))
                    .log("Sign-in check refused {} {}: SIGN_IN_CHALLENGE_REQUIRED, the person must first choose which active sign-in to end",
                            OpsLog.method(request), OpsLog.path(request));
            response.setStatus(401);
            response.setHeader("Cache-Control", "no-store");
            response.setContentType("application/json");
            response.getWriter().write("{\"code\":\"SIGN_IN_CHALLENGE_REQUIRED\",\"message\":\"Choose an active sign-in to continue.\"}");
            return;
        }
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
            chain.doFilter(request, response);
            return;
        }
        var session = request.getSession(false);
        boolean api = session != null && request.getRequestURI().startsWith("/bff/api/v1/");
        boolean read = "GET".equals(request.getMethod()) || "HEAD".equals(request.getMethod());
        boolean reusable = api && read && !request.getRequestURI().equals("/bff/api/v1/auth/csrf");
        String person = authentication.getName();
        if (reusable && Boolean.TRUE.equals(checks.passedRecently(session, person))) {
            chain.doFilter(request, response);
            return;
        }
        int status;
        // DLV-969: why a check did not pass, as a stable code and in words, for the log line.
        String reason, why;
        String types = null;
        Integer domain = null;
        /*
         * One check at a time for a session. A page sends several requests at once; when the access token was due for
         * renewal, each of them renewed it on its own, the renewal of one made the token of another invalid, that one
         * ended the session, and the ones that had passed then failed with a 500 on the ended session. Now the first
         * request renews and checks; the ones that waited find its result (a read), or check with the renewed token.
         */
        synchronized (SignInCheckSession.mutex(session)) {
            Boolean recent = session == null ? Boolean.FALSE : checks.passedRecently(session, person);
            if (recent == null) {
                status = 401; reason = "SESSION_ENDED"; why = "another request of this session ended the sign-in a moment ago";
            } else if (reusable && recent) {
                status = 200; reason = why = null;
            } else {
                try {
                    var client = tokens.authorize(authentication, request, response);
                    status = client == null ? 401 : domainClient.me(client, oauth.cloud() ? SignInProofSession.proof(request, false) : null);
                    if (client == null) { reason = "NO_PROVIDER_TOKENS"; why = "this session holds no provider tokens"; }
                    else { domain = status; reason = status == 401 ? "DOMAIN_SIGN_IN_ENDED" : "DOMAIN_CHECK_FAILED";
                        why = status == 401 ? "Domain says this sign-in has ended or was revoked" : "Domain answered HTTP " + status; }
                } catch (OAuth2AuthorizationException rejected) {
                    status = "invalid_grant".equals(rejected.getError().getErrorCode()) ? 401 : 503;
                    reason = status == 401 ? "SESSION_EXPIRED" : "TOKEN_REFRESH_FAILED";
                    why = status == 401 ? "Cognito refused the refresh token (invalid_grant)" : "the token refresh did not succeed";
                } catch (RuntimeException unavailable) {
                    status = 503;
                    reason = "DOMAIN_UNAVAILABLE"; types = OpsLog.types(unavailable); why = "Domain did not answer (" + types + ")";
                }
                if (status == 200 && api && !checks.remember(session, person)) {
                    // Signed out (or ended) while this check was on its way: the answer is "sign in again", never a 500.
                    status = 401; reason = "SESSION_ENDED"; why = "the session ended while the sign-in was being checked";
                } else if (status == 401) {
                    DevAccessSession.clearLearner(request);
                }
            }
        }
        if (status == 200) {
            chain.doFilter(request, response);
            return;
        }
        var line = (status == 401 ? OpsLog.refused("sign-in.check", reason) : OpsLog.failed("sign-in.check", reason))
                .addKeyValue("http.method", OpsLog.method(request)).addKeyValue("url.path", OpsLog.path(request));
        if (domain != null) line = line.addKeyValue("upstream.status", domain);
        if (types != null) line = line.addKeyValue("exception.types", types);
        line.log(status == 401 ? "Sign-in check failed for {} {}: {}, {}; the learner sign-in ends" : "Sign-in check failed for {} {}: {}, {}; answered 503",
                OpsLog.method(request), OpsLog.path(request), reason, why);
        response.setStatus(status == 401 ? 401 : 503);
        response.setHeader("Cache-Control", "no-store");
        response.setContentType("application/json");
        response.getWriter().write(status == 401
                ? "{\"code\":\"AUTHENTICATION_REQUIRED\",\"message\":\"Sign in again.\"}"
                : "{\"code\":\"SERVICE_UNAVAILABLE\",\"message\":\"Sign-in verification is temporarily unavailable.\"}");
    }
}
