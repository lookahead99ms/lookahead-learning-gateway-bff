package com.lookahead.gateway.client;

import com.lookahead.gateway.log.OpsLog;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.UserNotFoundException;

/**
 * DLV-969: the DEV gate's five-minute question to the Look Ahead pool, with the task role (IAM #7: AdminGetUser on
 * exactly the issuer's pool). A user the owner deleted is gone and a user they disabled is not enabled; both lose the gate.
 * Each call writes one {@code lookahead.upstream} line; the SDK makes no retries here.
 */
public final class DevAccessCognitoClient implements DevAccessClient {
    private final CognitoIdentityProviderClient client;
    private final String poolId;

    public DevAccessCognitoClient(String issuer, CognitoIdentityProviderClient client) {
        this.client = client;
        this.poolId = issuer.substring(issuer.lastIndexOf('/') + 1);
    }

    @Override public boolean allowed(String username) {
        try {
            var user = OpsLog.aws("cognito", "AdminGetUser", "pool " + poolId, false, () -> client.adminGetUser(AdminGetUserRequest.builder().userPoolId(poolId).username(username).build()));
            return Boolean.TRUE.equals(user.enabled());
        } catch (UserNotFoundException deleted) {
            return false;
        }
    }
}
