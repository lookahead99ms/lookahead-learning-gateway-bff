package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/** Secrets remain in the Gateway session; browser headers never select a Domain session. */
final class CloudGatewaySessions {
    static final String PROOF="lookaheadCloudProof", CHALLENGE="lookaheadCloudChallenge";
    record Result(int status,byte[] body,JsonNode data) {}
    private final OAuthSettings settings;
    private final RestClient http;
    CloudGatewaySessions(OAuthSettings settings,RestClient http){this.settings=settings;this.http=http;}
    static boolean restricted(HttpServletRequest request) {
        var session=request.getSession(false);
        return session!=null && session.getAttribute(CHALLENGE) instanceof String;
    }
    static String proof(HttpServletRequest request,boolean create){
        var session=request.getSession(create);if(session==null)return null;
        synchronized(session){
            Object current=session.getAttribute(PROOF);
            if(current instanceof String value)return value;
            if(!create)return null;
            byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);
            String value=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);session.setAttribute(PROOF,value);return value;
        }
    }
    static void apply(OAuthSettings settings,HttpServletRequest request,HttpHeaders headers){
        if(settings.cloud()){
            String proof=proof(request,false);
            if(proof!=null)headers.set("X-LookAhead-SignIn-Proof",proof);
        }
    }
    Result call(String action,String token,HttpServletRequest request,Map<String,?> body){
        if(!settings.cloud()||token==null)throw new IllegalStateException("Cloud session request requires provider credentials");
        boolean read=action.equals("inventory")||action.equals("challenge")||action.equals("profile")&&body==null;
        var call=http.method(read?HttpMethod.GET:HttpMethod.POST).uri(settings.domainApiUpstream()+"/internal/v1/cloud-sign-ins/"+action)
            .headers(headers->{headers.setBearerAuth(token);headers.set("X-LookAhead-Gateway-Secret",settings.gatewaySecret());apply(settings,request,headers);
                var session=request.getSession(false);if(session!=null&&session.getAttribute(CHALLENGE) instanceof String challenge)headers.set("X-LookAhead-Challenge",challenge);})
            .contentType(MediaType.APPLICATION_JSON);
        if(!read)call.body(body);
        return call.exchange((sent,received)->{
            byte[] bytes=received.getBody().readNBytes(16385);if(bytes.length>16384)throw new org.springframework.web.client.RestClientException("Invalid Domain response");
            JsonNode document;
            try {document=new JsonMapper().readTree(bytes);}
            catch(RuntimeException malformed){throw new org.springframework.web.client.RestClientException("Invalid Domain response");}
            if(document==null)throw new org.springframework.web.client.RestClientException("Invalid Domain response");
            return new Result(received.getStatusCode().value(),bytes,document.path("data"));
        });
    }
}
