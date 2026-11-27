package com.lookahead.gateway.proxy;

import com.lookahead.gateway.client.SignInDomainClient;
import com.lookahead.gateway.client.SignInTokenClient;
import com.lookahead.gateway.dto.ApiResponse;
import com.lookahead.gateway.log.OpsLog;
import com.lookahead.gateway.security.session.SignInProofSession;
import com.lookahead.gateway.security.session.SignInSession;
import com.lookahead.gateway.security.session.TestSessionState;
import com.lookahead.gateway.util.AccountMergeOffer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;

/**
 * DLV-969: forwards one account request of a cloud sign-in (sign-ins, sign-in challenge, profile, password, preferences,
 * links) to the Domain's cloud sign-in action of the same name, with the server-held token, and answers with the
 * Domain's body. The routes are in {@code AccountCloudController}.
 */
public final class AccountCloudProxy {
    private final SignInTokenClient tokens;
    private final OAuth2AuthorizedClientRepository clients;
    private final SignInDomainClient sessions;

    public AccountCloudProxy(SignInTokenClient tokens,OAuth2AuthorizedClientRepository clients,SignInDomainClient sessions){this.tokens=tokens;this.clients=clients;this.sessions=sessions;}

    public ResponseEntity<?> forward(HttpServletRequest request,HttpServletResponse response,Authentication authentication,Map<String,Object> body){
        String path=request.getRequestURI();String action=path.substring(path.lastIndexOf('/')+1);
        if(action.equals("sign-ins"))action="inventory";if(action.equals("sign-in-challenge"))action="challenge";
        // DLV-969: account actions are logged as account.<action> (revoke, label, password, ...); reads only when they fail.
        String event="account."+action;
        if(SignInProofSession.restricted(request)&&!Set.of("challenge","replace","cancel").contains(action))return refused(event,failure(401,"SIGN_IN_CHALLENGE_REQUIRED"),"the person must first choose which active sign-in to end");
        // DLV-969 S35: a test account has no sign-in, profile or password of its own to show or change.
        if(TestSessionState.active(authentication))return refused(event,failure(409,"TEST_SESSION"),"a test account has no sign-in, profile or password of its own");
        try {
            var client=tokens.authorize(authentication,request,response);
            if(client==null)return refused(event,failure(401,"AUTHENTICATION_REQUIRED"),"this session holds no provider tokens");
            var result=sessions.call(action,client.getAccessToken().getTokenValue(),SignInProofSession.proof(request,false),SignInProofSession.challenge(request),body);
            if(result.status()!=200){
                OpsLog.refusedByUpstream("Account action {} refused by Domain: {} (HTTP {})",event,action,result.body(),result.status());
                return ResponseEntity.status(result.status()>=500?503:result.status()).header("Cache-Control","no-store").contentType(MediaType.APPLICATION_JSON).body(result.body());
            }
            boolean ended=action.equals("cancel")||result.data().path("reauthenticationRequired").asBoolean(false);
            if(body!=null)OpsLog.success(event).addKeyValue("signIn.ended",ended)
                .log(ended?"Account action {} done; this sign-in ends and the person signs in again":"Account action {} done",action);
            if(action.equals("replace")) {
                String owner=result.data().path("accountId").asString("");if(owner.isEmpty())return failure(503,"SERVICE_UNAVAILABLE");
                // Retain the challenge secret for an owner-bound retry until the redirect completes.
                var data=new LinkedHashMap<String,Object>();data.put("accountId",owner);
                // DLV-969 S36: Domain decides mergeAvailable once the challenge is resolved; /bff/login then sends the offer.
                if(AccountMergeOffer.literalTrue(result.data().path("mergeAvailable"))){data.put("mergeAvailable",true);request.getSession().setAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE,Boolean.TRUE);}
                else request.getSession().removeAttribute(AccountMergeOffer.MERGE_AFTER_CHALLENGE);
                return ResponseEntity.ok().header("Cache-Control","no-store").body(ApiResponse.success(data));
            }
            if(ended){
                SignInSession.end(clients,authentication,request,response);
            }
            return ResponseEntity.ok().header("Cache-Control","no-store").contentType(MediaType.APPLICATION_JSON).body(result.body());
        } catch(RuntimeException error){return notCompleted(error,event,AccountCloudProxy::refused,AccountCloudProxy::failure,clients,authentication,request,response);}
    }
    /** A caller's own refusal line ({@code refused}) and its own answer shape ({@code failure}), handed to {@link #notCompleted}. */
    interface Refusal { ResponseEntity<?> refused(String event,ResponseEntity<?> answer,String why); }
    /**
     * The answer of both account forwarders when the call could not be completed: Cognito refusing the refresh token
     * ({@code invalid_grant}) ends this sign-in and answers 401; any other failed token refresh and a Domain that did not
     * answer are 503. Each is logged through the caller's own refusal line.
     */
    static ResponseEntity<?> notCompleted(RuntimeException error,String event,Refusal refusal,BiFunction<Integer,String,ResponseEntity<?>> failure,
            OAuth2AuthorizedClientRepository clients,Authentication authentication,HttpServletRequest request,HttpServletResponse response){
        if(error instanceof OAuth2AuthorizationException rejected){
            if("invalid_grant".equals(rejected.getError().getErrorCode())){
                SignInSession.end(clients,authentication,request,response);
                return refusal.refused(event,failure.apply(401,"AUTHENTICATION_REQUIRED"),"session expired: Cognito refused the refresh token (invalid_grant)");
            }
            return refusal.refused(event,failure.apply(503,"SERVICE_UNAVAILABLE"),"the token refresh did not succeed");
        }
        return refusal.refused(event,failure.apply(503,"SERVICE_UNAVAILABLE"),"Domain did not answer ("+OpsLog.types(error)+")");
    }
    /** One WARN line for an account request the Gateway BFF refused or could not complete: the code and why, never the body. */
    private static ResponseEntity<?> refused(String event,ResponseEntity<?> answer,String why){
        return OpsLog.refusedAnswer("Account request {} refused: {} ({})",event,answer,why);
    }
    private static ResponseEntity<?> failure(int status,String code){
        String message=code.equals("SIGN_IN_CHALLENGE_REQUIRED")?"Choose an active sign-in to continue.":code.equals("TEST_SESSION")?"Test accounts have no sign-in, profile or password of their own.":status==401?"Sign in again to continue.":"Sign-in service is unavailable. Retry shortly.";
        return ResponseEntity.status(status).header("Cache-Control","no-store").body(Map.of("code",code,"message",message));
    }
}
