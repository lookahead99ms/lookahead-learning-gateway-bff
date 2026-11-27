package com.lookahead.gateway.security.session;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;

/**
 * DLV-969: what a DEV test session keeps in this Gateway BFF session and how other classes ask about it: the sign-in token
 * of a test account, the staff sign-in kept aside, who holds the gate, the headers the Domain proxy sends for it, and
 * the two changes of the session itself (a test session starts; the staff sign-in comes back).
 */
public final class TestSessionState {
    public static final String SECRET_HEADER = "X-LookAhead-Gateway-Secret", HOLDER_HEADER = "X-LookAhead-Gate-Subject",
            ACCOUNT_HEADER = "X-LookAhead-Test-Account";
    /** The staff sign-in a test session was started from, kept in the session until Back to my account or sign-out. */
    public static final String STAFF_SIGN_IN = "lookaheadTestSessionStaffSignIn";
    private static final SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();
    private TestSessionState() {}

    /** This Gateway BFF session's sign-in while a test account is in use; the principal is the test account id. */
    public static final class TestSession extends AbstractAuthenticationToken {
        public final String accountId;
        public TestSession(String accountId) { super(List.of()); this.accountId = accountId; setAuthenticated(true); }
        @Override public Object getCredentials() { return null; }
        @Override public Object getPrincipal() { return accountId; }
    }

    public static boolean active(Authentication authentication) { return authentication instanceof TestSession; }

    /** Who opened this browser's DEV gate (their Cognito {@code sub}), while the gate is open; null otherwise. */
    public static String holder(HttpServletRequest request) {
        return DevAccessSession.current(request) instanceof DevAccessSession.State state && DevAccessSession.open(state, Instant.now()) ? state.subject() : null;
    }

    /** The proxy's headers for a test session; false (send nothing) when it is not one or the gate admission is gone. */
    public static boolean apply(OAuthClientDetails oauth, HttpServletRequest request, Authentication authentication, HttpHeaders headers) {
        String holder = holder(request);
        if (holder == null || !(authentication instanceof TestSession session)) return false;
        headers.set(SECRET_HEADER, oauth.domainSecret());
        headers.set(HOLDER_HEADER, holder);
        headers.set(ACCOUNT_HEADER, session.accountId);
        return true;
    }

    /** The staff sign-in kept aside by this session's test session, or null. */
    public static OAuth2AuthenticationToken staffSignIn(HttpServletRequest request) {
        var session = request.getSession(false);
        return session != null && session.getAttribute(STAFF_SIGN_IN) instanceof OAuth2AuthenticationToken staff ? staff : null;
    }

    /** Makes this Gateway BFF session a test session for {@code account}, once the Domain has approved the switch. */
    public static void start(HttpServletRequest request, HttpServletResponse response, Authentication authentication, UUID account) {
        // Who this session is changes, so its id rotates, as at sign-in; the gate admission stays in the session. Switching from
        // your own sign-in keeps it aside; switching between test accounts keeps the one already there.
        request.changeSessionId();
        // DLV-971: a test session started while signed out has no activity stamp yet; without one the idle filter would end it at once.
        request.getSession().setAttribute(SignInSession.LAST_ACTIVITY, Instant.now());
        if (authentication instanceof OAuth2AuthenticationToken staff) request.getSession().setAttribute(STAFF_SIGN_IN, staff);
        var context = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        context.setAuthentication(new TestSession(account.toString()));
        SecurityContextHolder.getContextHolderStrategy().setContext(context);
        contexts.saveContext(context, request, response);
    }

    /** Back to my account: {@code staff}, the sign-in kept aside when the test session started, is this session's sign-in again. */
    public static void end(HttpServletRequest request, HttpServletResponse response, OAuth2AuthenticationToken staff) {
        request.changeSessionId();
        request.getSession().removeAttribute(STAFF_SIGN_IN);
        var context = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        context.setAuthentication(staff);
        SecurityContextHolder.getContextHolderStrategy().setContext(context);
        contexts.saveContext(context, request, response);
    }
}
