package com.lookahead.gateway.security.handler;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.util.AccountMergeOffer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import java.io.IOException;

/** The browser redirect after an accepted OAuth sign-in; no token values reach the browser. */
public final class SignInSuccessHandler {
    private final OAuthClientDetails oauth;
    private final SignInCompletionHandler completion;
    public SignInSuccessHandler(OAuthClientDetails oauth,SignInCompletionHandler completion){this.oauth=oauth;this.completion=completion;}

    public void loginSucceeded(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) throws IOException {
        String next = completion.completeSignIn(request, response, authentication);
        if (AccountMergeOffer.mergeAvailable(request)) {
            // DLV-969 S36: the redirect sign-in cannot show the inbox panel, so the browser goes to the merge offer first.
            String provider = oauth.cloud() ? SignInCompletionHandler.provider(authentication) : "identity";
            OpsLog.success("sign-in.merge-offer").addKeyValue("provider", provider).addKeyValue("via", "oauth")
                    .log("Sign-in completed ({} via oauth) and other accounts share this person's verified email: redirected to the merge offer page", provider);
            next = AccountMergeOffer.mergeOffer(next);
        }
        response.sendRedirect(oauth.frontend() + next);
    }
}
