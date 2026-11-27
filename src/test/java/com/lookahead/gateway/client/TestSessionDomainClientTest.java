package com.lookahead.gateway.client;

import com.lookahead.gateway.log.LogCapture;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactoryTest;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.oauth.OAuthClientDetailsFactory;
import com.lookahead.gateway.security.session.TestSessionState;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import java.io.IOException;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * DLV-1015: the Domain's test-account calls, driven directly: what is sent, and what comes back as the client's own value.
 * The browser's answer is shaped from that value in TestSessionHandlerTest; the routes drive both in TestSessionControllerIntegrationTest.
 */
class TestSessionDomainClientTest {
    OAuthClientDetails oauth(){return OAuthClientDetailsFactory.from(new OAuthClientDetailsFactoryTest().production());}

    @Test void accountsAsksTheDomainWithTheSecretAndTheGateHolderAndNoBearerToken(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts")).andExpect(method(HttpMethod.GET))
            .andExpect(header(TestSessionState.SECRET_HEADER,oauth.domainSecret())).andExpect(header(TestSessionState.HOLDER_HEADER,"sub-admin"))
            .andExpect(headerDoesNotExist("Authorization")).andExpect(headerDoesNotExist(TestSessionState.ACCOUNT_HEADER))
            .andRespond(withSuccess("{\"data\":[]}",MediaType.APPLICATION_JSON));
        var answer=new TestSessionDomainClient(oauth,builder.build()).accounts("sub-admin");
        server.verify();
        assertThat(answer.status()).isEqualTo(200);
        assertThat(new String(answer.body(),StandardCharsets.UTF_8)).isEqualTo("{\"data\":[]}");
    }

    @Test void startPostsTheChosenAccountAndRelaysTheDomainsRefusal(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        var account=UUID.fromString("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a");
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/start")).andExpect(method(HttpMethod.POST))
            .andExpect(header(TestSessionState.SECRET_HEADER,oauth.domainSecret())).andExpect(header(TestSessionState.HOLDER_HEADER,"sub-admin"))
            .andExpect(headerDoesNotExist("Authorization")).andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
            .andExpect(content().json("{\"accountId\":\""+account+"\"}"))
            .andRespond(withStatus(HttpStatus.FORBIDDEN).contentType(MediaType.APPLICATION_JSON).body("{\"code\":\"TEST_ACCOUNT_FORBIDDEN\"}"));
        var answer=new TestSessionDomainClient(oauth,builder.build()).start("sub-admin",account);
        server.verify();
        assertThat(answer.status()).isEqualTo(403);
        assertThat(new String(answer.body(),StandardCharsets.UTF_8)).isEqualTo("{\"code\":\"TEST_ACCOUNT_FORBIDDEN\"}");
    }

    /** What the handler turns into 503, 502 and 503 (TestSessionHandlerTest) leaves the client as the Domain gave it. */
    @Test void aDomainErrorAnOversizedAnswerAndAFailedCallComeBackAsTheyAre(){
        var builder=RestClient.builder();var server=MockRestServiceServer.bindTo(builder).build();var oauth=oauth();
        var client=new TestSessionDomainClient(oauth,builder.build());
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts")).andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR).body("{}"));
        var error=client.accounts("sub-admin");
        assertThat(error.status()).isEqualTo(500);
        assertThat(new String(error.body(),StandardCharsets.UTF_8)).isEqualTo("{}");
        server.verify();server.reset();
        // Exactly the limit is an answer like any other; one byte more is read no further and its status is not asked for.
        assertThat(TestSessionDomainClient.RESPONSE_LIMIT).isEqualTo(256*1024);
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts"))
            .andRespond(withSuccess("x".repeat(TestSessionDomainClient.RESPONSE_LIMIT),MediaType.APPLICATION_JSON));
        var full=client.accounts("sub-admin");
        assertThat(full.status()).isEqualTo(200);
        assertThat(full.body()).hasSize(TestSessionDomainClient.RESPONSE_LIMIT);
        server.verify();server.reset();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts"))
            .andRespond(withSuccess("x".repeat(TestSessionDomainClient.RESPONSE_LIMIT+5),MediaType.APPLICATION_JSON));
        var large=client.accounts("sub-admin");
        assertThat(large.body()).hasSize(TestSessionDomainClient.RESPONSE_LIMIT+1);
        assertThat(large.status()).isZero();
        server.verify();server.reset();
        // A call that cannot be made leaves as the connection throws it; the client writes no line and shapes no answer.
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/accounts")).andRespond(request->{throw new IOException("synthetic outage");});
        try(var log=new LogCapture("lookahead.event")){
            assertThatThrownBy(()->client.accounts("sub-admin")).isInstanceOf(ResourceAccessException.class).hasCauseInstanceOf(IOException.class).hasRootCauseMessage("synthetic outage");
            assertThat(log.lines()).isEmpty();
        }
        server.verify();server.reset();
        server.expect(requestTo(oauth.domainApiUpstream()+"/internal/v1/test-sessions/start")).andRespond(request->{throw new IllegalStateException("synthetic transport failure");});
        assertThatThrownBy(()->client.start("sub-admin",UUID.fromString("2c7e9a4d-1b3f-4c5e-8d9a-0b1c2d3e4f5a"))).isInstanceOf(IllegalStateException.class).hasMessage("synthetic transport failure");
    }
}
