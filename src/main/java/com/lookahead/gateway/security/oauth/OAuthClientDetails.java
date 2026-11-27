package com.lookahead.gateway.security.oauth;

import java.net.URI;

/** Only deployment configuration selects service destinations. */
public record OAuthClientDetails(String issuer, String clientId, String clientSecret,
        String identityUpstream, String domainApiUpstream, String frontend, String managedLogin, String scopePrefix, String domainSecret) {
    public OAuthClientDetails(String issuer,String clientId,String clientSecret,String identityUpstream,String domainApiUpstream,String frontend){this(issuer,clientId,clientSecret,identityUpstream,domainApiUpstream,frontend,null,null,null);}
    public boolean cloud(){return managedLogin != null;}
    /** The AWS region named in the host of a Cognito pool issuer. */
    public static String region(String issuer) {
        return URI.create(issuer).getHost().split("\\.")[1];
    }
    @Override public String toString() { return "OAuthClientDetails[redacted]"; }
}
