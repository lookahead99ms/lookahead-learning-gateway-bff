package com.lookahead.gateway.client;

import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.TestSessionState;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import java.util.Map;
import org.springframework.web.client.RestClientException;

/**
 * The Domain's cloud sign-in calls: the bearer token and the Gateway BFF secret go with every one, the session's sign-in proof
 * (cloud only) and its pending challenge when the caller hands them in. The caller reads both from the session.
 */
public final class SignInDomainClient {
    public record Result(int status,byte[] body,JsonNode data) {}
    private final OAuthClientDetails oauth;
    private final RestClient http;
    public SignInDomainClient(OAuthClientDetails oauth,RestClient http){this.oauth=oauth;this.http=http;}
    public Result call(String action,String token,String proof,String challenge,Map<String,?> body){
        if(!oauth.cloud()||token==null)throw new IllegalStateException("Cloud session request requires provider credentials");
        boolean read=action.equals("inventory")||action.equals("challenge")||action.equals("profile")&&body==null;
        var call=http.method(read?HttpMethod.GET:HttpMethod.POST).uri(oauth.domainApiUpstream()+"/internal/v1/cloud-sign-ins/"+action)
            .headers(headers->{headers.setBearerAuth(token);headers.set(TestSessionState.SECRET_HEADER,oauth.domainSecret());SignInProofSession.apply(oauth,proof,headers);
                if(challenge!=null)headers.set("X-LookAhead-Challenge",challenge);})
            .contentType(MediaType.APPLICATION_JSON);
        if(!read)call.body(body);
        return call.exchange((sent,received)->{
            int status=received.getStatusCode().value();
            byte[] bytes=received.getBody().readNBytes(16385);if(bytes.length>16384)throw unreadable(action,status,"ANSWER_TOO_LARGE","larger than 16 KB",null);
            JsonNode document;
            try {document=new JsonMapper().readTree(bytes);}
            catch(RuntimeException malformed){throw unreadable(action,status,"ANSWER_NOT_JSON","not JSON",malformed);}
            if(document==null)throw unreadable(action,status,"ANSWER_EMPTY","empty",null);
            return new Result(status,bytes,document.path("data"));
        });
    }
    /** Asks the Domain whether this sign-in is still valid ({@code /api/v1/auth/me}); the answer is the HTTP status alone. */
    public int me(OAuth2AuthorizedClient client,String proof){
        return http.get().uri(oauth.domainApiUpstream() + "/api/v1/auth/me")
                            .headers(headers -> {headers.setBearerAuth(client.getAccessToken().getTokenValue());SignInProofSession.apply(oauth,proof,headers);})
                            .exchange((sent, received) -> received.getStatusCode().value());
    }
    /**
     * DLV-969: Domain answered, but not in a form the Gateway BFF can read. Callers report this as "Domain unavailable", so this
     * line says what actually came back: the action, Domain's HTTP status and why (never the body or the parser's message).
     */
    private static RestClientException unreadable(String action,int status,String reason,String words,RuntimeException failure){
        var line=OpsLog.failed("cloud-session."+action,reason).addKeyValue("upstream.service","domain").addKeyValue("upstream.status",status);
        if(failure!=null)line=line.addKeyValue("exception.types",OpsLog.types(failure));
        line.log("Domain's answer to cloud sign-in {} (HTTP {}) was unreadable: {} ({}{})",action,status,reason,words,failure==null?"":": "+OpsLog.types(failure));
        return new RestClientException("Invalid Domain response");
    }
}
