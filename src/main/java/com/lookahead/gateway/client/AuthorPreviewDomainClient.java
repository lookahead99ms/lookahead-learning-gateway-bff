package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.SignInProofSession;
import java.net.URI;
import org.springframework.web.client.RestClient;

/**
 * Asks the Domain whether the signed-in person may read author previews right now. It uses the author-preview connection
 * (bean {@code authorPreviewHttp}), which never follows a redirect, and returns the Domain's status as it is: 204 means yes.
 */
public final class AuthorPreviewDomainClient {
    private final OAuthClientDetails oauth;
    private final RestClient http;

    public AuthorPreviewDomainClient(OAuthClientDetails oauth, RestClient http) {
        this.oauth = oauth;
        this.http = http;
    }

    /** The HTTP status of the Domain's access check for this server-held token (and sign-in proof, in the cloud). */
    public int access(String token, String proof) {
        return http.get().uri(URI.create(oauth.domainApiUpstream() + "/api/v1/author/previews/access"))
                .headers(headers -> {headers.setBearerAuth(token);SignInProofSession.apply(oauth,proof,headers);})
                .exchange((sent, received) -> received.getStatusCode().value());
    }
}
