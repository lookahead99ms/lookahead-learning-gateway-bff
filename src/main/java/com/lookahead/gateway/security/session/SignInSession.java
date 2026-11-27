package com.lookahead.gateway.security.session;

import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;

/** The signed-in session as a whole: ending it drops the provider tokens, the server session and the security context. */
public final class SignInSession {
    /** The session attribute holding when this sign-in was last active; the idle filter ends a sign-in that has none or an old one. */
    public static final String LAST_ACTIVITY="lookaheadLearnerActivity";
    private SignInSession() {}

    /** Ends this sign-in on the server: the person signs in again. Used when an account action ends it or the provider refuses to renew it. */
    public static void end(OAuth2AuthorizedClientRepository clients,Authentication authentication,HttpServletRequest request,HttpServletResponse response) {
        clients.removeAuthorizedClient(OAuthClientRegistrationFactory.REGISTRATION_ID,authentication,request,response);
        var session=request.getSession(false);if(session!=null)session.invalidate();SecurityContextHolder.clearContext();
    }
}
