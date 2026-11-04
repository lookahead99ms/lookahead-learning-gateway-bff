package com.lookahead.learning.content.gateway;

import java.net.URI;
import java.time.Duration;
import software.amazon.awssdk.auth.credentials.ContainerCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.retries.DefaultRetryStrategy;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * DLV-969: the DEV gate's five-minute question to the Look Ahead pool, with the task role (IAM #7: AdminGetUser on
 * exactly the issuer's pool). A user the owner deleted is gone and a user they disabled is not enabled; both lose the gate.
 * Each call writes one {@code lookahead.upstream} line; the SDK makes no retries here.
 */
final class CognitoAdmissionCheck implements DevAdmission.Account {
    private final CognitoIdentityProviderClient client;
    private final String poolId;

    CognitoAdmissionCheck(String issuer, CognitoIdentityProviderClient client) {
        this.client = client;
        this.poolId = issuer.substring(issuer.lastIndexOf('/') + 1);
    }

    static CognitoAdmissionCheck forIssuer(String issuer) {
        String region = URI.create(issuer).getHost().split("\\.")[1];
        return new CognitoAdmissionCheck(issuer, CognitoIdentityProviderClient.builder().region(Region.of(region))
            .credentialsProvider(ContainerCredentialsProvider.builder().build())
            .httpClientBuilder(software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(2)).socketTimeout(Duration.ofSeconds(3)))
            .overrideConfiguration(c -> c.apiCallTimeout(Duration.ofSeconds(4)).apiCallAttemptTimeout(Duration.ofSeconds(3))
                .retryStrategy(DefaultRetryStrategy.doNotRetry()))
            .build());
    }

    String poolId() { return poolId; }

    @Override public boolean allowed(String username) {
        try {
            var user = OpsLog.aws("cognito", "AdminGetUser", () -> client.adminGetUser(AdminGetUserRequest.builder().userPoolId(poolId).username(username).build()));
            return Boolean.TRUE.equals(user.enabled());
        } catch (UserNotFoundException deleted) {
            return false;
        }
    }
}
