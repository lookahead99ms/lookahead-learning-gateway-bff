package com.lookahead.gateway.security.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.lookahead.gateway.security.filter.DevAccessFilter;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContextHolder;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserRequest;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AdminGetUserResponse;

/** The DEV gate's beans, built by calling the bean methods directly. */
class DevAccessConfigurationTest {
    @AfterEach void clear(){SecurityContextHolder.clearContext();}
    @Test void gateConfigurationIsDevOnlyAndRegistersTheFilterAheadOfSecurity() {
        var config=new DevAccessConfiguration();
        assertThrows(IllegalStateException.class,()->config.devAccessGate(new MockEnvironment().withProperty("app.deployment-environment","prod")));
        assertNotNull(config.devAccessGate(new MockEnvironment().withProperty("app.deployment-environment","dev")));
        var oauth=new OAuthClientDetails("https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example","client","synthetic-secret","http://identity","http://domain","https://dev.example");
        var registration=config.devAccessFilter(oauth);assertEquals(-110,registration.getOrder());assertInstanceOf(DevAccessFilter.class,registration.getFilter());
    }
    /** The pool is asserted through the {@code AdminGetUser} request the SDK client receives from the client this configuration builds. */
    @Test void theTaskRoleClientIsBuiltForTheIssuersRegion() {
        String issuer = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example";
        var oauth = new OAuthClientDetails(issuer, "client", "synthetic-secret", "http://identity", "http://domain", "https://dev.example");
        var sdk = mock(CognitoIdentityProviderClient.class);
        when(sdk.adminGetUser(any(AdminGetUserRequest.class))).thenReturn(AdminGetUserResponse.builder().enabled(true).build());
        var config = spy(new DevAccessConfiguration());
        doReturn(sdk).when(config).devAccessCognitoIdp(oauth);
        assertTrue(config.devAccessCognitoClient(oauth).allowed("google_1"));
        var sent = ArgumentCaptor.forClass(AdminGetUserRequest.class);
        verify(sdk).adminGetUser(sent.capture());
        assertEquals("us-east-2_Example", sent.getValue().userPoolId());
        assertEquals("us-east-2", OAuthClientDetails.region(issuer));
        var built = new DevAccessConfiguration().devAccessCognitoIdp(oauth);
        assertEquals("us-east-2", built.serviceClientConfiguration().region().id());
        built.close();
    }
}
