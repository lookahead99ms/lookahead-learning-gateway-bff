package com.lookahead.gateway.controller;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.dto.CsrfView;
import com.lookahead.gateway.security.handler.SignOutHandler;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientRegistrationFactory;
import com.lookahead.gateway.security.oauth.SignInProvider;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.util.AccountMergeOffer;
import com.lookahead.gateway.util.SignInReturnDestination;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import java.util.*;
import java.io.IOException;

// Exception, decided 2026-11-25 (DLV-1015): login and startOAuth hold the sign-in reuse decision and build the redirect,
// which is more than a route (rule 5: a controller holds routes only). The reauthenticate handling that the security
// exception record reviews sits in that code, and the record binds this file; moving the code to a handler in another
// file means the record would have to bind that file, which is the owner's security review. It stays here until then.
@RestController
@Profile("gateway")
public class SignInController {
    private final OAuthClientDetails oauth;
    private final OAuth2AuthorizedClientRepository clients;
    private final SignInDomainClient signInDomainClient;
    private final SignOutHandler signOut;
    public SignInController(OAuthClientDetails oauth,OAuth2AuthorizedClientRepository clients,SignInDomainClient signInDomainClient,SignOutHandler signOut) {
        this.oauth=oauth;this.clients=clients;this.signInDomainClient=signInDomainClient;this.signOut=signOut;
    }
    /** DLV-969: {@code provider} is google or password when the person chose one on our sign-in page; anything else opens Cognito's page. */
    @GetMapping("/bff/login")
    public void login(@RequestParam(required=false) String returnTo,@RequestParam(required=false) String provider,HttpServletRequest request,HttpServletResponse response) throws IOException {
        // A browser may request a fresh OAuth flow, never skip verification and
        // continue into the sign-in reuse path.
        if(oauth.cloud()&&"true".equals(request.getParameter("reauthenticate"))) {
            startOAuth(returnTo,provider,request,response);
            return;
        }
        if(oauth.cloud()) {
            var authentication=SecurityContextHolder.getContext().getAuthentication();
            if(authentication instanceof OAuth2AuthenticationToken) {
                var client=clients.<OAuth2AuthorizedClient>loadAuthorizedClient(OAuthClientRegistrationFactory.REGISTRATION_ID,authentication,request);
                if(client!=null) {
                    int status=signInDomainClient.me(client,SignInProofSession.proof(request,false));
                    if(status==200){
                        var session=request.getSession();session.removeAttribute(SignInProofSession.CHALLENGE);
                        // DLV-969 S36: a resolved challenge whose replace answer said mergeAvailable goes to the merge offer, once.
                        boolean merge=Boolean.TRUE.equals(session.getAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE));session.removeAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE);
                        String target=SignInReturnDestination.safeReturn(returnTo);
                        response.sendRedirect(oauth.frontend()+(merge?AccountMergeOffer.mergeOffer(target):target));return;
                    }
                }
            }
        }
        startOAuth(returnTo,provider,request,response);
    }
    private void startOAuth(String returnTo,String provider,HttpServletRequest request,HttpServletResponse response) throws IOException {
        request.getSession().setAttribute(SignInReturnDestination.SESSION_ATTRIBUTE,SignInReturnDestination.safeReturn(returnTo));
        // Only the two known names travel on; the resolver re-checks them (and whether Google is switched on).
        String chosen=SignInProvider.from(provider,true).map(p->"?"+SignInProvider.PARAMETER+"="+p.parameter).orElse("");
        response.setHeader("Cache-Control","no-store");response.sendRedirect(oauth.frontend()+"/oauth2/authorization/lookahead"+chosen);
    }
    @GetMapping("/bff/api/v1/auth/csrf")
    public ApiResponse<CsrfView> csrf(CsrfToken token,HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");return ApiResponse.success(CsrfView.from(token));
    }
    @PostMapping("/bff/api/v1/auth/logout")
    public ApiResponse<Map<String,String>> logout(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
        return signOut.logout(request,response,authentication);
    }
    @GetMapping("/bff/logout/complete")
    public void cloudLogoutComplete(HttpServletResponse response)throws IOException {
        signOut.cloudLogoutComplete(response);
    }
}
