package com.lookahead.gateway.security.handler;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

/**
 * DLV-1015: which provider a sign-in came from, for the log lines of the completion and of the merge offer. provider(...)
 * moved to SignInCompletionHandler unchanged. The completion itself is driven through the OAuth callback in
 * GatewayBffApplicationCloudIntegrationTest and through our own password page in PasswordSignInHandlerTest.
 */
class SignInCompletionHandlerTest {
    static Authentication signIn(Map<String, Object> more) {
        var claims = new HashMap<String, Object>(Map.of("sub", "synthetic-subject"));
        claims.putAll(more);
        var now = Instant.parse("2026-11-02T20:00:00Z");
        var user = new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")), new OidcIdToken("synthetic-id-token", now, now.plusSeconds(300), claims));
        return new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");
    }

    @Test void aUserFederatedFromGoogleIsRecognisedByTheIdentitiesClaimOrByTheUsernamePrefix() {
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("identities", List.of(Map.of("providerName", "Google", "userId", "1")))))).isEqualTo("google");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("identities", List.of("not a map", Map.of("providerName", "SAML"), Map.of("providerName", "google")))))).isEqualTo("google");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("cognito:username", "Google_1234567890")))).isEqualTo("google");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("cognito:username", "google_1234567890")))).isEqualTo("google");
    }

    @Test void everyOtherSignInIsThePoolsOwnEmailAndPassword() {
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("cognito:username", "priya@example.invalid")))).isEqualTo("password");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of()))).isEqualTo("password");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("identities", List.of(Map.of("providerName", "SAML")), "cognito:username", "saml_1")))).isEqualTo("password");
        assertThat(SignInCompletionHandler.provider(signIn(Map.of("identities", "Google")))).isEqualTo("password");
        // Not an OIDC principal (a test session, for example): nothing to read, so the pool's own sign-in.
        assertThat(SignInCompletionHandler.provider(new TestingAuthenticationToken("someone", "n/a"))).isEqualTo("password");
    }

    // DLV-1015: moved line for line from the cloud integration test, which now lives in the root package; firstName is package-private.
    @Test void firstNameComesFromTheClaimsAndIsLettersOnly() {
        Function<Map<String,Object>,Authentication> signIn=extra->{
            var claims=new HashMap<String,Object>(Map.of("sub","s"));claims.putAll(extra);
            var token=new OidcIdToken("t",Instant.now().minusSeconds(5),Instant.now().plusSeconds(60),claims);
            var user=new DefaultOidcUser(List.of(new SimpleGrantedAuthority("ROLE_USER")),token);
            return new OAuth2AuthenticationToken(user,user.getAuthorities(),"lookahead");};
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("given_name","Mohiddin","name","Mohiddin Shaik")))).isEqualTo("Mohiddin");
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("name","Shree  Ram")))).isEqualTo("Shree");
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("given_name"," Zoë-Anne ")))).isEqualTo("Zoë-Anne");
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("given_name","R2D2")))).isNull();
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("given_name","a".repeat(41))))).isNull();
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of("given_name","<b>x</b>")))).isNull();
        assertThat(SignInCompletionHandler.firstName(signIn.apply(Map.of()))).isNull();
        assertThat(SignInCompletionHandler.firstName(null)).isNull();
    }
}
