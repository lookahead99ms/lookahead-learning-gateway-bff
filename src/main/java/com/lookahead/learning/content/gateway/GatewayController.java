package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import com.lookahead.learning.content.dto.ApiResponse;
import com.lookahead.learning.content.dto.CsrfView;
import jakarta.servlet.http.*;
import org.springframework.context.annotation.Profile;
import org.springframework.http.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.*;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

@RestController
@Profile("gateway")
public class GatewayController {
    private final OAuthSettings settings;
    private final OAuth2AuthorizedClientManager manager;
    private final OAuth2AuthorizedClientRepository clients;
    private final RestClient http;
    public GatewayController(OAuthSettings settings,OAuth2AuthorizedClientManager manager,OAuth2AuthorizedClientRepository clients,RestClient http) {
        this.settings=settings;this.manager=manager;this.clients=clients;this.http=http;
    }
    @GetMapping("/bff/login")
    public void login(@RequestParam(required=false) String returnTo,HttpServletRequest request,HttpServletResponse response) throws java.io.IOException {
        request.getSession().setAttribute("learningReturnTo",GatewayConfiguration.safeReturn(returnTo));
        response.setHeader("Cache-Control","no-store");response.sendRedirect(settings.frontend()+"/oauth2/authorization/lookahead");
    }
    @GetMapping("/bff/api/v1/auth/csrf")
    public ApiResponse<CsrfView> csrf(CsrfToken token,HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");return ApiResponse.success(new CsrfView(token.getToken(),token.getHeaderName(),token.getParameterName()));
    }
    @PostMapping("/bff/api/v1/auth/logout")
    public ApiResponse<Map<String,String>> logout(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
        var client=clients.loadAuthorizedClient("lookahead",authentication,request);
        if(client!=null) {
            revoke(client.getAccessToken().getTokenValue());
            if(client.getRefreshToken()!=null) revoke(client.getRefreshToken().getTokenValue());
        }
        String idToken=authentication.getPrincipal() instanceof OidcUser user?user.getIdToken().getTokenValue():null;
        clients.removeAuthorizedClient("lookahead",authentication,request,response);
        var session=request.getSession(false);if(session!=null)session.invalidate();SecurityContextHolder.clearContext();
        String url=settings.issuer()+"/connect/logout?post_logout_redirect_uri="+encode(settings.frontend()+"/sign-in");
        if(idToken!=null)url+="&id_token_hint="+encode(idToken);
        response.setHeader("Cache-Control","no-store");return ApiResponse.success(Map.of("logoutUrl",url));
    }
    private void revoke(String token) {
        var form=new LinkedMultiValueMap<String,String>();form.add("token",token);
        http.post().uri(settings.identityUpstream()+"/oauth2/revoke").headers(headers->headers.setBasicAuth(settings.clientId(),settings.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().toBodilessEntity();
    }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }

    @RequestMapping(value={"/bff/api/v1/**","/content/**"},method={RequestMethod.GET,RequestMethod.POST,RequestMethod.DELETE})
    public ResponseEntity<byte[]> proxy(HttpServletRequest request,HttpServletResponse response,Authentication authentication) throws java.io.IOException {
        String route=request.getRequestURI();String upstreamPath=route.startsWith("/bff/")?route.substring(4):route;
        boolean content=upstreamPath.startsWith("/content/") && request.getMethod().equals("GET");
        boolean account=upstreamPath.equals("/api/v1/auth/me") || upstreamPath.equals("/api/v1/account-catalog")
                || upstreamPath.equals("/api/v1/support") || upstreamPath.equals("/api/v1/plans") || upstreamPath.startsWith("/api/v1/plans/");
        boolean execution = executionRoute(request.getMethod(), upstreamPath) && request.getQueryString() == null;
        boolean authorReview = authorReviewRoute(request.getMethod(), upstreamPath)
                && (!"POST".equals(request.getMethod()) || request.getQueryString() == null);
        if(!content && !account && !execution && !authorReview)return ResponseEntity.notFound().build();
        if (authorReview && !(authentication instanceof OAuth2AuthenticationToken)) return ResponseEntity.status(401).build();
        int bodyLimit = authorReview ? 16 * 1024 : execution ? 512 * 1024 : 8 * 1024 * 1024;
        byte[] body=request.getInputStream().readNBytes(bodyLimit + 1);
        if(body.length>bodyLimit)return ResponseEntity.status(413).build();
        String target=settings.domainApiUpstream()+upstreamPath+(request.getQueryString()==null?"":"?"+request.getQueryString());
        var outgoing=http.method(HttpMethod.valueOf(request.getMethod())).uri(java.net.URI.create(target)).headers(headers->{
            for(String name:List.of("Content-Type","Accept","Idempotency-Key","If-Match","X-LookAhead-Account")) {
                String value=request.getHeader(name);if(value!=null)headers.set(name,value);
            }
        });
        if(authentication instanceof OAuth2AuthenticationToken) {
            var client=manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead").principal(authentication)
                    .attributes(attributes->{attributes.put(HttpServletRequest.class.getName(),request);attributes.put(HttpServletResponse.class.getName(),response);}).build());
            if(client==null)return ResponseEntity.status(401).build();
            outgoing.headers(headers->headers.setBearerAuth(client.getAccessToken().getTokenValue()));
        }
        // No browser Authorization, Cookie, Origin, forwarding headers, or arbitrary upstream is relayed.
        return outgoing.body(body).exchange((sent,received)->{
            int responseLimit = execution ? 512 * 1024 : 16 * 1024 * 1024;
            byte[] bytes=received.getBody().readNBytes(responseLimit + 1);
            if(bytes.length>responseLimit)return ResponseEntity.status(502).body(new byte[0]);
            var headers=new HttpHeaders();headers.setCacheControl("no-store");
            if(received.getHeaders().getContentType()!=null)headers.setContentType(received.getHeaders().getContentType());
            headers.set("X-Content-Type-Options","nosniff");
            return new ResponseEntity<>(bytes,headers,received.getStatusCode());
        });
    }
    static boolean authorReviewRoute(String method, String path) {
        return "GET".equals(method) && "/api/v1/author/review-artifacts".equals(path)
                || ("GET".equals(method) || "POST".equals(method))
                && path.matches("/api/v1/author/review-artifacts/[a-z0-9][a-z0-9-]{0,79}/events");
    }

    static boolean executionRoute(String method, String path) {
        return "GET".equals(method) && "/api/v1/executions/capabilities".equals(path)
                || "POST".equals(method) && "/api/v1/executions/jobs".equals(path)
                || ("GET".equals(method) || "DELETE".equals(method))
                && path.matches("/api/v1/executions/jobs/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }
}
