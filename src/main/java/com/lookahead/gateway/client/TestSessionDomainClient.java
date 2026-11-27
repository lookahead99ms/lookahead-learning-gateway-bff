package com.lookahead.gateway.client;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.TestSessionState;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * The Domain's test-account calls (DLV-969 S35): the Gateway BFF secret and the gate holder go with each one, never a bearer token.
 * Each call returns what the Domain answered; a call that cannot be made or read throws, as the connection throws it.
 * {@code TestSessionHandler} shapes the browser's answer from either.
 */
public final class TestSessionDomainClient {
    public static final int RESPONSE_LIMIT = 256 * 1024;

    /**
     * What the Domain answered: its status, and its body read up to one byte past {@link #RESPONSE_LIMIT}. A body longer
     * than the limit says the answer was too large; the status of such an answer is not read and is 0 here.
     */
    public record Answer(int status, byte[] body) {}

    private final OAuthClientDetails oauth;
    private final RestClient http;

    public TestSessionDomainClient(OAuthClientDetails oauth, RestClient http) { this.oauth = oauth; this.http = http; }

    /** The test accounts this gate holder may use, as the Domain answers. */
    public Answer accounts(String holder) {
        return relay(() -> http.get().uri(oauth.domainApiUpstream() + "/internal/v1/test-sessions/accounts")
                .headers(headers -> domain(headers, holder)));
    }

    /** Asks the Domain to approve this gate holder's switch to one test account. */
    public Answer start(String holder, UUID account) {
        return relay(() -> http.post().uri(oauth.domainApiUpstream() + "/internal/v1/test-sessions/start")
                .headers(headers -> domain(headers, holder)).contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("accountId", account.toString())));
    }

    private void domain(HttpHeaders headers, String holder) {
        headers.set(TestSessionState.SECRET_HEADER, oauth.domainSecret());
        headers.set(TestSessionState.HOLDER_HEADER, holder);
    }

    private Answer relay(Supplier<RestClient.RequestHeadersSpec<?>> call) {
        return call.get().exchange((sent, received) -> {
            byte[] bytes = received.getBody().readNBytes(RESPONSE_LIMIT + 1);
            if (bytes.length > RESPONSE_LIMIT) return new Answer(0, bytes);
            int status = received.getStatusCode().value();
            return new Answer(status, bytes);
        });
    }
}
