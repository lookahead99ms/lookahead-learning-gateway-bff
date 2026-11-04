package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * DLV-969 S36: the person's own merge of accounts that share their verified email. The Web calls these same-origin;
 * the Gateway relays them to the Domain's account routes with the server-held token and sign-in proof, and passes the
 * Domain's status and body through unchanged (202, 200, 400, 404, 409, 422). Sign-in and CSRF are enforced by
 * {@link GatewayConfiguration} ({@code /api/v1/account/**} is authenticated; every POST needs the session token).
 */
@RestController
@Profile("gateway")
@ConditionalOnExpression("'${app.deployment-environment:}' == 'dev' || '${app.deployment-environment:}' == 'prod'")
@RequestMapping("/api/v1/account/merge")
public class AccountMergeProxyController {
    static final int MAX_BODY = 16 * 1024;
    /** The candidates answer lists each account's study plans; generous, still bounded. */
    static final int MAX_ANSWER = 1024 * 1024;
    static final String TOKEN = "[A-Za-z0-9_-]{43}";
    private final OAuthSettings settings;
    private final OAuth2AuthorizedClientManager manager;
    private final OAuth2AuthorizedClientRepository clients;
    private final RestClient http;

    public AccountMergeProxyController(OAuthSettings settings, OAuth2AuthorizedClientManager manager,
            OAuth2AuthorizedClientRepository clients, RestClient http) {
        this.settings = settings; this.manager = manager; this.clients = clients; this.http = http;
    }

    @PostMapping("/request")
    public ResponseEntity<?> request(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        return forward(HttpMethod.POST, "/request", request, response, authentication);
    }

    @GetMapping("/{token}")
    public ResponseEntity<?> candidates(@PathVariable String token, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        if (!token.matches(TOKEN)) return failure(404, "MERGE_TOKEN_INVALID");
        return forward(HttpMethod.GET, "/" + token, request, response, authentication);
    }

    @PostMapping("/{token}")
    public ResponseEntity<?> merge(@PathVariable String token, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        if (!token.matches(TOKEN)) return failure(404, "MERGE_TOKEN_INVALID");
        return forward(HttpMethod.POST, "/" + token, request, response, authentication);
    }

    private ResponseEntity<?> forward(HttpMethod method, String suffix, HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        // DLV-969: logged as merge.request / merge.candidates / merge.merge, like the other account actions; never the token.
        String event = suffix.equals("/request") ? "merge.request" : method == HttpMethod.GET ? "merge.candidates" : "merge.merge";
        // The same refusals as the other account routes: a session at the sign-in challenge, or a test account.
        if (CloudGatewaySessions.restricted(request)) return refused(event, failure(401, "SIGN_IN_CHALLENGE_REQUIRED"), "the person must first choose which active sign-in to end");
        if (TestSessionController.active(authentication)) return refused(event, failure(409, "TEST_SESSION"), "a test account never takes part in a merge");
        if (!(authentication instanceof OAuth2AuthenticationToken)) return refused(event, failure(401, "AUTHENTICATION_REQUIRED"), "not signed in with the provider");
        byte[] body = method == HttpMethod.POST ? request.getInputStream().readNBytes(MAX_BODY + 1) : null;
        if (body != null && body.length > MAX_BODY) return refused(event, failure(413, "REQUEST_TOO_LARGE"), "the body is larger than " + MAX_BODY + " bytes");
        try {
            var client = manager.authorize(OAuth2AuthorizeRequest.withClientRegistrationId("lookahead").principal(authentication)
                .attributes(a -> { a.put(HttpServletRequest.class.getName(), request); a.put(HttpServletResponse.class.getName(), response); }).build());
            if (client == null) return refused(event, failure(401, "AUTHENTICATION_REQUIRED"), "this session holds no provider tokens");
            var call = http.method(method).uri(java.net.URI.create(settings.domainApiUpstream() + "/api/v1/account/merge" + suffix))
                .headers(headers -> { headers.setBearerAuth(client.getAccessToken().getTokenValue()); CloudGatewaySessions.apply(settings, request, headers); });
            if (body != null) call.contentType(MediaType.APPLICATION_JSON).body(body);
            return call.<ResponseEntity<?>>exchange((sent, received) -> {
                byte[] bytes = received.getBody().readNBytes(MAX_ANSWER + 1);
                if (bytes.length > MAX_ANSWER) return refused(event, failure(503, "SERVICE_UNAVAILABLE"), "Domain's answer is larger than " + MAX_ANSWER + " bytes");
                int status = received.getStatusCode().value();
                if (status >= 300) {
                    String code = OpsLog.code(bytes); code = code == null ? "HTTP_" + status : code;
                    (status >= 500 ? OpsLog.failed(event, code) : OpsLog.refused(event, code)).addKeyValue("upstream.status", status)
                        .log("Merge step {} refused by Domain: {} (HTTP {})", event, code, status);
                } else OpsLog.success(event).addKeyValue("upstream.status", status)
                    .log(event.equals("merge.request") ? "Merge step {} accepted by Domain: if there is anything to merge, the link is on its way by email"
                        : event.equals("merge.candidates") ? "Merge step {} done: Domain listed the accounts behind the emailed link"
                        : "Merge step {} done: Domain merged the accounts; this sign-in ends", event);
                var headers = new HttpHeaders(); headers.setCacheControl("no-store"); headers.set("X-Content-Type-Options", "nosniff");
                if (received.getHeaders().getContentType() != null) headers.setContentType(received.getHeaders().getContentType());
                return new ResponseEntity<>(bytes, headers, received.getStatusCode());
            });
        } catch (org.springframework.security.oauth2.core.OAuth2AuthorizationException rejected) {
            if ("invalid_grant".equals(rejected.getError().getErrorCode())) {
                clients.removeAuthorizedClient("lookahead", authentication, request, response);
                var session = request.getSession(false); if (session != null) session.invalidate(); SecurityContextHolder.clearContext();
                return refused(event, failure(401, "AUTHENTICATION_REQUIRED"), "session expired: Cognito refused the refresh token (invalid_grant)");
            }
            return refused(event, failure(503, "SERVICE_UNAVAILABLE"), "the token refresh did not succeed");
        } catch (RuntimeException unavailable) {
            return refused(event, failure(503, "SERVICE_UNAVAILABLE"), "Domain did not answer (" + RequestLog.types(unavailable) + ")");
        }
    }

    /** One WARN line for a merge request the Gateway refused or could not complete: the code and why, never the body or token. */
    private static ResponseEntity<?> refused(String event, ResponseEntity<?> answer, String why) {
        int status = answer.getStatusCode().value();
        String code = answer.getBody() instanceof Map<?, ?> body && body.get("code") instanceof String value ? value : "HTTP_" + status;
        (status >= 500 ? OpsLog.failed(event, code) : OpsLog.refused(event, code)).addKeyValue("http.status", status)
            .log("Merge step {} refused: {} ({})", event, code, why);
        return answer;
    }

    private static ResponseEntity<?> failure(int status, String code) {
        return ResponseEntity.status(status).header("Cache-Control", "no-store").contentType(MediaType.APPLICATION_JSON).body(Map.of("code", code));
    }
}
