package com.lookahead.gateway.security.session;

import com.lookahead.gateway.security.oauth.OAuthClientDetails;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import java.security.SecureRandom;
import java.util.Base64;

/** Secrets remain in the Gateway BFF session; browser headers never select a Domain session. */
public final class SignInProofSession {
    public static final String PROOF="lookaheadCloudProof", CHALLENGE="lookaheadCloudChallenge";
    /** The header that carries this session's sign-in proof to the Domain. */
    public static final String PROOF_HEADER="X-LookAhead-SignIn-Proof";
    private SignInProofSession(){}
    public static boolean restricted(HttpServletRequest request) {
        var session=request.getSession(false);
        return session!=null && session.getAttribute(CHALLENGE) instanceof String;
    }
    public static String proof(HttpServletRequest request,boolean create){
        var session=request.getSession(create);if(session==null)return null;
        synchronized(session){
            Object current=session.getAttribute(PROOF);
            if(current instanceof String value)return value;
            if(!create)return null;
            byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);
            String value=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);session.setAttribute(PROOF,value);return value;
        }
    }
    /** The pending sign-in challenge this session holds, or null. Never creates a session. */
    public static String challenge(HttpServletRequest request){
        var session=request.getSession(false);return session!=null&&session.getAttribute(CHALLENGE) instanceof String challenge?challenge:null;
    }
    public static void apply(OAuthClientDetails oauth,HttpServletRequest request,HttpHeaders headers){
        if(oauth.cloud()){
            String proof=proof(request,false);
            apply(oauth,proof,headers);
        }
    }
    /** Sets the proof header on a call to the Domain: in the cloud only, and only when there is a proof. */
    public static void apply(OAuthClientDetails oauth,String proof,HttpHeaders headers){
        if(oauth.cloud()&&proof!=null)headers.set(PROOF_HEADER,proof);
    }
}
