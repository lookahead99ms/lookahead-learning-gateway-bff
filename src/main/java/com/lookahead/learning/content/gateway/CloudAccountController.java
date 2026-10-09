package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.CsrfView;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
public class CloudAccountController {
    private final OAuthSettings settings;
    private final OAuth2AuthorizedClientManager manager;
    private final OAuth2AuthorizedClientRepository clients;
    private final CloudGatewaySessions sessions;
    public CloudAccountController(OAuthSettings settings,OAuth2AuthorizedClientManager manager,OAuth2AuthorizedClientRepository clients,RestClient http){this.settings=settings;this.manager=manager;this.clients=clients;this.sessions=new CloudGatewaySessions(settings,http);}
    @GetMapping("/api/v1/auth/options")
    public ApiResponse<?> options(HttpServletResponse response){response.setHeader("Cache-Control","no-store");return ApiResponse.success(Map.of("registration",false,"google",false,"oauth",true,"managedLogin",true));}
    @GetMapping("/api/v1/auth/csrf")
    public ApiResponse<CsrfView> csrf(CsrfToken token,HttpServletResponse response){response.setHeader("Cache-Control","no-store");return ApiResponse.success(new CsrfView(token.getToken(),token.getHeaderName(),token.getParameterName()));}
    @GetMapping({"/api/v1/account/sign-ins","/api/v1/auth/sign-in-challenge","/api/v1/account/profile"})
    public ResponseEntity<?> read(HttpServletRequest request,HttpServletResponse response,Authentication authentication){return forward(request,response,authentication,null);}
    @PostMapping({"/api/v1/account/sign-ins/revoke","/api/v1/account/sign-ins/revoke-others","/api/v1/account/sign-ins/label","/api/v1/auth/sign-in-challenge/replace","/api/v1/auth/sign-in-challenge/cancel","/api/v1/account/profile","/api/v1/account/password"})
    public ResponseEntity<?> mutate(@RequestBody Map<String,Object> body,HttpServletRequest request,HttpServletResponse response,Authentication authentication){return forward(request,response,authentication,body);}
    private ResponseEntity<?> forward(HttpServletRequest request,HttpServletResponse response,Authentication authentication,Map<String,Object> body){
        String path=request.getRequestURI();String action=path.substring(path.lastIndexOf('/')+1);
        if(action.equals("sign-ins"))action="inventory";if(action.equals("sign-in-challenge"))action="challenge";
        if(CloudGatewaySessions.restricted(request)&&!java.util.Set.of("challenge","replace","cancel").contains(action))return failure(401,"SIGN_IN_CHALLENGE_REQUIRED");
        try {
            var client=manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead").principal(authentication).attributes(a->{a.put(HttpServletRequest.class.getName(),request);a.put(HttpServletResponse.class.getName(),response);}).build());
            if(client==null)return failure(401,"AUTHENTICATION_REQUIRED");
            var result=sessions.call(action,client.getAccessToken().getTokenValue(),request,body);
            if(result.status()!=200)return ResponseEntity.status(result.status()>=500?503:result.status()).header("Cache-Control","no-store").contentType(org.springframework.http.MediaType.APPLICATION_JSON).body(result.body());
            if(action.equals("replace")) {
                String owner=result.data().path("accountId").asString("");if(owner.isEmpty())return failure(503,"SERVICE_UNAVAILABLE");
                // Retain the challenge secret for an owner-bound retry until the redirect completes.
                return ResponseEntity.ok().header("Cache-Control","no-store").body(ApiResponse.success(Map.of("accountId",owner)));
            }
            if(action.equals("cancel")||result.data().path("reauthenticationRequired").asBoolean(false)){
                clients.removeAuthorizedClient("lookahead",authentication,request,response);
                var session=request.getSession(false);if(session!=null)session.invalidate();SecurityContextHolder.clearContext();
            }
            return ResponseEntity.ok().header("Cache-Control","no-store").contentType(org.springframework.http.MediaType.APPLICATION_JSON).body(result.body());
        } catch(org.springframework.security.oauth2.core.OAuth2AuthorizationException rejected){
            if("invalid_grant".equals(rejected.getError().getErrorCode())){
                clients.removeAuthorizedClient("lookahead",authentication,request,response);
                var session=request.getSession(false);if(session!=null)session.invalidate();SecurityContextHolder.clearContext();
                return failure(401,"AUTHENTICATION_REQUIRED");
            }
            return failure(503,"SERVICE_UNAVAILABLE");
        } catch(RuntimeException error){return failure(503,"SERVICE_UNAVAILABLE");}
    }
    private static ResponseEntity<?> failure(int status,String code){
        String message=code.equals("SIGN_IN_CHALLENGE_REQUIRED")?"Choose an active sign-in to continue.":status==401?"Sign in again to continue.":"Sign-in service is unavailable. Retry shortly.";
        return ResponseEntity.status(status).header("Cache-Control","no-store").body(Map.of("code",code,"message",message));
    }
}
