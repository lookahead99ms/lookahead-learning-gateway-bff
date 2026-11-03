package com.lookahead.learning.content.gateway;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/** DLV-969: the gate's five-minute question names exactly the issuer's pool; deleted or disabled means no gate. */
class CognitoAdmissionCheckTest {
    static final String ISSUER = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example";

    @Test void enabledUsersStayDisabledAndDeletedUsersDoNot() {
        var client = mock(CognitoIdentityProviderClient.class);
        var check = new CognitoAdmissionCheck(ISSUER, client);
        assertEquals("us-east-2_Example", check.poolId());
        var request = AdminGetUserRequest.builder().userPoolId("us-east-2_Example").username("google_1").build();
        when(client.adminGetUser(request)).thenReturn(AdminGetUserResponse.builder().enabled(true).build());
        assertTrue(check.allowed("google_1"));
        when(client.adminGetUser(request)).thenReturn(AdminGetUserResponse.builder().enabled(false).build());
        assertFalse(check.allowed("google_1"));
        when(client.adminGetUser(request)).thenReturn(AdminGetUserResponse.builder().build());
        assertFalse(check.allowed("google_1"));
        when(client.adminGetUser(any(AdminGetUserRequest.class))).thenThrow(UserNotFoundException.builder().message("gone").build());
        assertFalse(check.allowed("google_1"));
    }
    @Test void aPoolThatDoesNotAnswerIsNotADecision() {
        var client = mock(CognitoIdentityProviderClient.class);
        when(client.adminGetUser(any(AdminGetUserRequest.class))).thenThrow(NotAuthorizedException.builder().message("denied").build());
        assertThrows(NotAuthorizedException.class, () -> new CognitoAdmissionCheck(ISSUER, client).allowed("google_1"));
    }
    @Test void theTaskRoleClientIsBuiltForTheIssuersRegion() {
        assertEquals("us-east-2_Example", CognitoAdmissionCheck.forIssuer(ISSUER).poolId());
    }
}
