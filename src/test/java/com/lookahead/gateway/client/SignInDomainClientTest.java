package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.session.SignInProofSession;
import ch.qos.logback.classic.Level;
import com.lookahead.gateway.log.LogCapture;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClientException;
import java.time.Instant;
import org.springframework.http.HttpMethod;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class SignInDomainClientTest {
    /** DLV-1015: the client no longer reads the session; it sends what it is handed, the proof in cloud mode only. */
    @Test void withoutAProofOrChallengeNeitherHeaderIsSentAndLocallyAProofIsNeverSent(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/cloud-sign-ins/inventory")).andExpect(method(HttpMethod.GET))
            .andExpect(header("Authorization","Bearer synthetic-token")).andExpect(header("X-LookAhead-Gateway-Secret",oauth.domainSecret()))
            .andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof")).andExpect(headerDoesNotExist("X-LookAhead-Challenge"))
            .andRespond(withSuccess("{\"data\":{}}",MediaType.APPLICATION_JSON));
        assertThat(new SignInDomainClient(oauth,builder.build()).call("inventory","synthetic-token",null,null,null).status()).isEqualTo(200);server.verify();
        // A challenge without a proof travels alone, and a proof without a challenge too.
        server.reset();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/cloud-sign-ins/challenge"))
            .andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof")).andExpect(header("X-LookAhead-Challenge","c".repeat(43)))
            .andRespond(withSuccess("{\"data\":{}}",MediaType.APPLICATION_JSON));
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/cloud-sign-ins/profile"))
            .andExpect(header("X-LookAhead-SignIn-Proof","p".repeat(43))).andExpect(headerDoesNotExist("X-LookAhead-Challenge"))
            .andRespond(withSuccess("{\"data\":{}}",MediaType.APPLICATION_JSON));
        var cloud=new SignInDomainClient(oauth,builder.build());
        cloud.call("challenge","synthetic-token",null,"c".repeat(43),null);cloud.call("profile","synthetic-token","p".repeat(43),null,null);server.verify();
        // Outside the cloud the cloud calls are refused before anything is sent, whatever is handed in.
        var local=new OAuthClientDetails("http://localhost","test","synthetic-secret","http://identity","http://domain","http://localhost");
        var localBuilder=RestClient.builder();var localServer=MockRestServiceServer.bindTo(localBuilder).build();
        assertThatIllegalStateException().isThrownBy(()->new SignInDomainClient(local,localBuilder.build()).call("inventory","synthetic-token","p".repeat(43),"c".repeat(43),null))
            .withMessage("Cloud session request requires provider credentials");
        assertThatIllegalStateException().isThrownBy(()->new SignInDomainClient(oauth,builder.build()).call("inventory",null,null,null,null));
        // The sign-in check works locally too: the bearer token alone, even when a proof is handed in.
        var registration=ClientRegistration.withRegistrationId("lookahead").clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        var client=new OAuth2AuthorizedClient(registration,"account",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-token",Instant.now(),Instant.now().plusSeconds(300)));
        for(String proof:new String[]{"p".repeat(43),null}){
            localServer.reset();
            localServer.expect(requestTo("http://domain/api/v1/auth/me")).andExpect(header("Authorization","Bearer synthetic-token"))
                .andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof")).andRespond(withSuccess());
            assertThat(new SignInDomainClient(local,localBuilder.build()).me(client,proof)).isEqualTo(200);localServer.verify();
        }
        server.reset();
        server.expect(requestTo(oauth.domainApiUpstream()+"/api/v1/auth/me")).andExpect(headerDoesNotExist("X-LookAhead-SignIn-Proof")).andRespond(withSuccess());
        assertThat(cloud.me(client,null)).isEqualTo(200);server.verify();
    }
    OAuthClientDetails oauth(){return OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());}
    @Test void browserCannotChooseSessionProofAndChallengeStaysServerSide(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        var request=new MockHttpServletRequest();request.addHeader("X-LookAhead-SignIn-Proof","attacker");request.addHeader("X-LookAhead-Gateway-Secret","attacker");
        String proof=SignInProofSession.proof(request,true);assertThat(proof).hasSize(43);assertThat(SignInProofSession.proof(request,true)).isEqualTo(proof);
        request.getSession().setAttribute(SignInProofSession.CHALLENGE,"c".repeat(43));
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/cloud-sign-ins/replace"))
            .andExpect(header("Authorization","Bearer synthetic-token")).andExpect(header("X-LookAhead-SignIn-Proof",proof))
            .andExpect(header("X-LookAhead-Gateway-Secret",oauth.domainSecret())).andExpect(header("X-LookAhead-Challenge","c".repeat(43)))
            .andRespond(withSuccess("{\"data\":{\"accountId\":\"synthetic-owner\"}}",MediaType.APPLICATION_JSON));
        var result=new SignInDomainClient(oauth,builder.build()).call("replace","synthetic-token",SignInProofSession.proof(request,false),SignInProofSession.challenge(request),Map.of("signInId","synthetic-selected"));
        assertThat(result.status()).isEqualTo(200);server.verify();
        assertThat(SignInProofSession.proof(new MockHttpServletRequest(),false)).isNull();
    }
    @Test void signInCheckAsksTheDomainWithTheBearerTokenAndThisSessionsProofAndAnswersTheStatus(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        var request=new MockHttpServletRequest();request.addHeader("X-LookAhead-SignIn-Proof","attacker");
        String proof=SignInProofSession.proof(request,true);
        var registration=ClientRegistration.withRegistrationId("lookahead").clientId("test")
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).redirectUri("http://localhost/callback")
            .authorizationUri("http://localhost/authorize").tokenUri("http://localhost/token").build();
        var client=new OAuth2AuthorizedClient(registration,"account",
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,"synthetic-token",Instant.now(),Instant.now().plusSeconds(300)));
        server.expect(requestTo(oauth.domainApiUpstream()+"/api/v1/auth/me")).andExpect(method(HttpMethod.GET))
            .andExpect(header("Authorization","Bearer synthetic-token")).andExpect(header("X-LookAhead-SignIn-Proof",proof))
            .andExpect(headerDoesNotExist("X-LookAhead-Gateway-Secret")).andExpect(headerDoesNotExist("Cookie"))
            .andRespond(withStatus(HttpStatus.FORBIDDEN));
        assertThat(new SignInDomainClient(oauth,builder.build()).me(client,SignInProofSession.proof(request,false))).isEqualTo(403);server.verify();
    }

    /**
     * DLV-969 (owner, 2026-11-04): each fallback that used to answer 502 or 503 without a word now writes one WARN line with
     * what was being done and why: a stable reason code, the upstream status and exception types. Never a body or a token.
     */
    @Nested class FallbackReason {
    static final String SECRET = "synthetic-body-secret";
    static final String TOKEN = "synthetic-server-token";
    final LogCapture log = new LogCapture("lookahead.event");

    @AfterEach void close() { log.close(); }

    void reason(String action, String reason) {
        assertThat(log.lines()).isNotEmpty();
        assertThat(log.last().getLevel()).isEqualTo(Level.WARN);
        assertThat(LogCapture.pairs(log.last())).contains("event.action=" + action, "reason=" + reason);
        log.assertNothing(SECRET, TOKEN);
    }

    @Test void anUnreadableDomainAnswerIsNotReportedAsDomainBeingDown() {
        var oauth = OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());
        var builder = RestClient.builder(); var server = MockRestServiceServer.bindTo(builder).build();
        server.expect(requestTo(oauth.domainApiUpstream() + "/internal/v1/cloud-sign-ins/admit"))
                .andRespond(withSuccess("<html>" + SECRET + "</html>", MediaType.TEXT_HTML));
        server.expect(requestTo(oauth.domainApiUpstream() + "/internal/v1/cloud-sign-ins/admit"))
                .andRespond(withStatus(HttpStatus.BAD_GATEWAY).body("x".repeat(16385)));
        var sessions = new SignInDomainClient(oauth, builder.build());
        assertThatThrownBy(() -> sessions.call("admit", TOKEN, null, null, Map.of())).isInstanceOf(RestClientException.class);
        reason("cloud-session.admit", "ANSWER_NOT_JSON");
        assertThat(log.last().getFormattedMessage()).startsWith("Domain's answer to cloud sign-in admit (HTTP 200) was unreadable: ANSWER_NOT_JSON (not JSON: ");
        assertThat(LogCapture.pairs(log.last())).contains("upstream.service=domain", "upstream.status=200");
        assertThatThrownBy(() -> sessions.call("admit", TOKEN, null, null, Map.of())).isInstanceOf(RestClientException.class);
        reason("cloud-session.admit", "ANSWER_TOO_LARGE");
        assertThat(log.last().getFormattedMessage()).isEqualTo("Domain's answer to cloud sign-in admit (HTTP 502) was unreadable: ANSWER_TOO_LARGE (larger than 16 KB)");
        server.verify();
    }
    }
}
