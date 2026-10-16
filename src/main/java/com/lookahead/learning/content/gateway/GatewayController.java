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
        // A browser may request a fresh OAuth flow, never skip verification and
        // continue into the sign-in reuse path.
        if(settings.cloud()&&"true".equals(request.getParameter("reauthenticate"))) {
            startOAuth(returnTo,request,response);
            return;
        }
        if(settings.cloud()) {
            var authentication=SecurityContextHolder.getContext().getAuthentication();
            if(authentication instanceof OAuth2AuthenticationToken) {
                var client=clients.<OAuth2AuthorizedClient>loadAuthorizedClient("lookahead",authentication,request);
                if(client!=null) {
                    int status=http.get().uri(settings.domainApiUpstream()+"/api/v1/auth/me").headers(h->{h.setBearerAuth(client.getAccessToken().getTokenValue());CloudGatewaySessions.apply(settings,request,h);}).exchange((sent,received)->received.getStatusCode().value());
                    if(status==200){request.getSession().removeAttribute(CloudGatewaySessions.CHALLENGE);response.sendRedirect(settings.frontend()+GatewayConfiguration.safeReturn(returnTo));return;}
                }
            }
        }
        startOAuth(returnTo,request,response);
    }
    private void startOAuth(String returnTo,HttpServletRequest request,HttpServletResponse response) throws java.io.IOException {
        request.getSession().setAttribute("learningReturnTo",GatewayConfiguration.safeReturn(returnTo));
        response.setHeader("Cache-Control","no-store");response.sendRedirect(settings.frontend()+"/oauth2/authorization/lookahead");
    }
    @GetMapping("/bff/api/v1/auth/csrf")
    public ApiResponse<CsrfView> csrf(CsrfToken token,HttpServletResponse response) {
        response.setHeader("Cache-Control","no-store");return ApiResponse.success(new CsrfView(token.getToken(),token.getHeaderName(),token.getParameterName()));
    }
    @PostMapping("/bff/api/v1/auth/logout")
    public ApiResponse<Map<String,String>> logout(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
        if(settings.cloud())return cloudLogout(request,response,authentication);
        var client=clients.loadAuthorizedClient("lookahead",authentication,request);
        if(client!=null) {
            revoke(client.getAccessToken().getTokenValue());
            if(client.getRefreshToken()!=null) revoke(client.getRefreshToken().getTokenValue());
        }
        String idToken=authentication.getPrincipal() instanceof OidcUser user?user.getIdToken().getTokenValue():null;
        clients.removeAuthorizedClient("lookahead",authentication,request,response);
        DevAdmission.clearLearner(request);
        String url=settings.issuer()+"/connect/logout?post_logout_redirect_uri="+encode(settings.frontend()+"/sign-in");
        if(idToken!=null)url+="&id_token_hint="+encode(idToken);
        response.setHeader("Cache-Control","no-store");return ApiResponse.success(Map.of("logoutUrl",url));
    }
    private ApiResponse<Map<String,String>> cloudLogout(HttpServletRequest request,HttpServletResponse response,Authentication authentication) {
        var client=manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead").principal(authentication)
            .attributes(a->{a.put(HttpServletRequest.class.getName(),request);a.put(HttpServletResponse.class.getName(),response);}).build());
        boolean providerConfirmed=false;
        if(client!=null) {
            var result=new CloudGatewaySessions(settings,http).call("logout",client.getAccessToken().getTokenValue(),request,Map.of());
            if(result.status()!=200&&result.status()!=401)throw new org.springframework.web.client.RestClientException("Domain sign-out could not be confirmed");
            if(client.getRefreshToken()!=null) {
                try {
                    var form=new LinkedMultiValueMap<String,String>();form.add("token",client.getRefreshToken().getTokenValue());form.add("token_type_hint","refresh_token");
                    http.post().uri(settings.managedLogin()+"/oauth2/revoke").headers(h->h.setBasicAuth(settings.clientId(),settings.clientSecret()))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().toBodilessEntity();providerConfirmed=true;
                } catch(RuntimeException unavailable) { /* Durable Domain denial already committed. Report provider uncertainty. */ }
            }
        }
        clients.removeAuthorizedClient("lookahead",authentication,request,response);
        DevAdmission.clearLearner(request);
        response.setHeader("Cache-Control","no-store");
        return ApiResponse.success(Map.of("logoutUrl",settings.frontend()+"/bff/logout/complete","providerRevocationConfirmed",Boolean.toString(providerConfirmed)));
    }
    @GetMapping("/bff/logout/complete")
    public void cloudLogoutComplete(HttpServletResponse response)throws java.io.IOException {
        if(!settings.cloud()){response.setStatus(404);return;}
        response.setHeader("Cache-Control","no-store");
        response.sendRedirect(settings.managedLogin()+"/logout?client_id="+encode(settings.clientId())+"&logout_uri="+encode(settings.frontend()+"/sign-in"));
    }
    private void revoke(String token) {
        var form=new LinkedMultiValueMap<String,String>();form.add("token",token);
        http.post().uri(settings.identityUpstream()+"/oauth2/revoke").headers(headers->headers.setBasicAuth(settings.clientId(),settings.clientSecret()))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).body(form).retrieve().toBodilessEntity();
    }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8); }

    /** DLV-928: platform review uploads carry up to six 5 MB images (20 MB) plus the item text. */
    static final int PLATFORM_REVIEW_BODY_BYTES = 21 * 1024 * 1024;
    @RequestMapping(value={"/bff/api/v1/**","/content/**"},method={RequestMethod.GET,RequestMethod.POST,RequestMethod.PUT,RequestMethod.DELETE})
    public ResponseEntity<byte[]> proxy(HttpServletRequest request,HttpServletResponse response,Authentication authentication) throws java.io.IOException {
        String route=request.getRequestURI();String upstreamPath=route.startsWith("/bff/")?route.substring(4):route;
        boolean content=upstreamPath.startsWith("/content/") && request.getMethod().equals("GET");
        boolean account=upstreamPath.equals("/api/v1/auth/me") || upstreamPath.equals("/api/v1/account-catalog")
                || upstreamPath.equals("/api/v1/support") || upstreamPath.equals("/api/v1/plans") || upstreamPath.startsWith("/api/v1/plans/");
        boolean staffAccess = ("GET".equals(request.getMethod()) && java.util.Set.of("/api/v1/account/permissions", "/api/v1/admin/access", "/api/v1/admin/access/catalog").contains(upstreamPath)
                || "POST".equals(request.getMethod()) && java.util.Set.of("/api/v1/admin/access", "/api/v1/admin/access/lookup", "/api/v1/auth/invitations/activate").contains(upstreamPath)) && request.getQueryString()==null;
        boolean membership = membershipRoute(request.getMethod(),upstreamPath) && request.getQueryString()==null;
        boolean execution = executionRoute(request.getMethod(), upstreamPath) && request.getQueryString() == null;
        boolean authorReview = authorReviewRoute(request.getMethod(), upstreamPath)
                && (!"POST".equals(request.getMethod()) || request.getQueryString() == null);
        boolean platformReview = platformReviewRoute(request.getMethod(), upstreamPath)
                && ("GET".equals(request.getMethod()) || request.getQueryString() == null);
        // PUT exists only for platform reviews; every other route keeps its earlier methods.
        if("PUT".equals(request.getMethod()) && !platformReview)return ResponseEntity.status(405).header(HttpHeaders.CACHE_CONTROL,"no-store").build();
        if(!content && !account && !execution && !authorReview && !platformReview && !staffAccess && !membership)return ResponseEntity.notFound().build();
        if ((authorReview || platformReview || staffAccess || membership && !Set.of("/api/v1/membership/plans","/api/v1/sales/active").contains(upstreamPath)) && !(authentication instanceof OAuth2AuthenticationToken)) return ResponseEntity.status(401).build();
        int bodyLimit = (authorReview || staffAccess) ? 16 * 1024 : execution ? 512 * 1024 : platformReview ? PLATFORM_REVIEW_BODY_BYTES : 8 * 1024 * 1024;
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
            outgoing.headers(headers->{headers.setBearerAuth(client.getAccessToken().getTokenValue());CloudGatewaySessions.apply(settings,request,headers);});
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

    private static final String PLATFORM_REVIEW_ID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    static boolean platformReviewRoute(String method, String path) {
        String root = "/api/v1/platform-reviews", item = root + "/" + PLATFORM_REVIEW_ID;
        return switch (method) {
            case "GET" -> path.equals(root) || path.equals(root + "/me") || path.matches(item)
                    || path.matches(item + "/attachments/" + PLATFORM_REVIEW_ID);
            case "POST" -> path.equals(root);
            case "PUT" -> path.matches(item) || path.matches(item + "/triage");
            case "DELETE" -> path.matches(item);
            default -> false;
        };
    }

    static boolean membershipRoute(String method,String path) {
        String uuid="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
        return switch(method) {
            case "GET" -> Set.of("/api/v1/membership/plans","/api/v1/sales/active","/api/v1/account/access-records","/api/v1/account/access-summary","/api/v1/admin/test-accounts").contains(path)
                || path.matches("/api/v1/account/purchases/"+uuid) || path.matches("/api/v1/admin/accounts/"+uuid+"/(access-records|access-summary)");
            case "POST" -> Set.of("/api/v1/account/purchases","/api/v1/account/purchases/quote","/api/v1/admin/sales").contains(path)
                || path.matches("/api/v1/admin/test-accounts/"+uuid+"/reset")
                || path.matches("/api/v1/admin/accounts/"+uuid+"/plan-upgrades") || path.matches("/api/v1/admin/sales/"+uuid+"/stop")
                || path.matches("/api/v1/admin/membership/plans/[a-z-]{1,40}/price");
            default -> false;
        };
    }
    static boolean executionRoute(String method, String path) {
        return "GET".equals(method) && "/api/v1/executions/capabilities".equals(path)
                || "POST".equals(method) && "/api/v1/executions/jobs".equals(path)
                || ("GET".equals(method) || "DELETE".equals(method))
                && path.matches("/api/v1/executions/jobs/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");
    }
}
