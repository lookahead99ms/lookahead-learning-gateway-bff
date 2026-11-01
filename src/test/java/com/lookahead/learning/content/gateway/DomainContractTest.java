package com.lookahead.learning.content.gateway;

import com.lookahead.learning.content.oauth.OAuthSettings;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;

/**
 * DLV-968 T13: the Gateway owns {@code contracts/domain-api-v1.json}, the list of every Domain call it makes.
 * Each example is driven through the Gateway's own code against a mock Domain, and every Domain path literal in
 * {@code src/main/java} must be covered by the file, so neither side can drift silently.
 */
class DomainContractTest {
    static final Path CONTRACT = Path.of(System.getProperty("user.dir"), "src/test/resources/contracts/domain-api-v1.json");
    static final Path MAIN = Path.of(System.getProperty("user.dir"), "src/main/java");
    static final String UPSTREAM = "http://domain-api:8080";
    static final OAuthSettings LOCAL = new OAuthSettings("http://127.0.0.1:4331", "lookahead-domain-contract",
            "synthetic-client-secret-for-domain-contract", "http://identity:8080", UPSTREAM, "http://127.0.0.1:4331");
    static final Pattern DOMAIN_LITERAL = Pattern.compile("\"(/(?:api/v1|content|internal/v1)/[^\"]*)\"");
    static final Pattern FRONTEND_LITERAL = Pattern.compile("frontend\\(\\)\\s*\\+\\s*\"(/[^\"?&]*)");
    static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "DELETE");

    static JsonNode contract() throws IOException {
        return JsonMapper.builder().build().readTree(Files.readString(CONTRACT));
    }

    static List<JsonNode> entries(JsonNode contract, String... keys) {
        var list = new ArrayList<JsonNode>();
        for (String key : keys) contract.path(key).forEach(list::add);
        return list;
    }

    static List<String> strings(JsonNode array) {
        var list = new ArrayList<String>();
        array.forEach(node -> list.add(node.asString()));
        return list;
    }

    /** A path template such as {@code /api/v1/plans/{id}} or {@code /content/**} as a regex over concrete paths. */
    static Pattern template(String path) {
        var regex = new StringBuilder("^");
        for (String segment : path.substring(1).split("/", -1)) {
            regex.append('/');
            if (segment.equals("**")) regex.append(".+");
            else if (segment.startsWith("{") && segment.endsWith("}")) regex.append("[^/]+");
            else regex.append(Pattern.quote(segment));
        }
        return Pattern.compile(regex.append('$').toString());
    }

    static String source(Path file) {
        try { return Files.readString(file); } catch (IOException error) { throw new IllegalStateException(error); }
    }

    static List<Path> mainSources() throws IOException {
        try (Stream<Path> files = Files.walk(MAIN)) {
            return files.filter(file -> file.toString().endsWith(".java")).sorted().toList();
        }
    }

    @Test void contractEntriesAreWellFormedAndUnique() throws IOException {
        var contract = contract();
        assertThat(contract.path("schema").asString()).isEqualTo("gateway-domain-contract/v1");
        assertThat(contract.path("consumer").asString()).isEqualTo("lookahead99ms/lookahead-learning-gateway-bff");
        assertThat(contract.path("provider").asString()).isEqualTo("lookahead99ms/lookahead-learning-domain-api");
        var ids = new LinkedHashSet<String>();
        var routes = new LinkedHashSet<String>();
        var all = entries(contract, "calls", "forwardedWithoutProvider");
        assertThat(all).isNotEmpty();
        for (JsonNode entry : all) {
            String id = entry.path("id").asString(), method = entry.path("method").asString(), path = entry.path("path").asString();
            assertThat(ids.add(id)).as("duplicate id " + id).isTrue();
            assertThat(METHODS).as(id).contains(method);
            assertThat(path).as(id).startsWith("/");
            assertThat(routes.add(method + " " + path)).as("duplicate route " + method + " " + path).isTrue();
            assertThat(entry.path("example").asString()).as(id + " example matches its template").matches(template(path));
            assertThat(entry.path("callers").size()).as(id + " names its callers").isPositive();
        }
        for (JsonNode call : contract.path("calls")) {
            String id = call.path("id").asString();
            var statuses = new ArrayList<Integer>();
            call.path("statuses").forEach(status -> statuses.add(status.asInt()));
            assertThat(statuses).as(id + " success statuses").isNotEmpty().allMatch(status -> status >= 200 && status < 300);
            for (String key : List.of("reads", "readsOptional"))
                for (String field : strings(call.path(key))) assertThat(field).as(id + " " + key).startsWith("data");
            if (call.path("method").asString().equals("GET")) assertThat(call.has("exampleBody")).as(id + " GET has no body").isFalse();
        }
        for (JsonNode entry : contract.path("forwardedWithoutProvider"))
            assertThat(entry.has("statuses")).as(entry.path("id").asString() + " has no provider statuses").isFalse();
        assertThat(strings(contract.path("webPaths"))).contains("/", "/index.html").doesNotHaveDuplicates();
    }

    @Test void everyProxiedEntryIsForwardedByTheGatewayToTheContractPathUnchanged() throws Exception {
        var contract = contract();
        var user = new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "synthetic-user"), "sub");
        var authentication = new OAuth2AuthenticationToken(user, user.getAuthorities(), "lookahead");
        var registration = new GatewayClientConfiguration().gatewayClient(LOCAL).findByRegistrationId("lookahead");
        var manager = mock(OAuth2AuthorizedClientManager.class);
        when(manager.authorize(any())).thenReturn(new OAuth2AuthorizedClient(registration, authentication.getName(),
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "synthetic-server-held-token", Instant.now(), Instant.now().plusSeconds(600))));
        int proxied = 0;
        for (JsonNode entry : entries(contract, "calls", "forwardedWithoutProvider")) {
            if (!strings(entry.path("callers")).contains("GatewayController.proxy")) continue;
            proxied++;
            String id = entry.path("id").asString(), method = entry.path("method").asString(), example = entry.path("example").asString();
            int status = entry.path("statuses").isEmpty() ? 404 : entry.path("statuses").get(0).asInt();
            var builder = RestClient.builder();
            var domain = MockRestServiceServer.bindTo(builder).build();
            var expectation = domain.expect(requestTo(UPSTREAM + example)).andExpect(method(HttpMethod.valueOf(method)));
            expectation.andRespond(status == 204 || status == 404 ? withStatus(HttpStatus.valueOf(status))
                    : withStatus(HttpStatus.valueOf(status)).contentType(MediaType.APPLICATION_JSON).body("{\"data\":null,\"timestamp\":\"2026-10-31T00:00:00Z\"}"));
            var controller = new GatewayController(LOCAL, manager, mock(OAuth2AuthorizedClientRepository.class), builder.build());
            var request = new MockHttpServletRequest(method, example.startsWith("/content/") ? example : "/bff" + example);
            if (entry.has("requestContentType")) {
                String type = entry.path("requestContentType").asString();
                request.setContentType(type.startsWith("multipart/") ? type + "; boundary=synthetic" : type);
                request.setContent("{}".getBytes(StandardCharsets.UTF_8));
            }
            var response = controller.proxy(request, new MockHttpServletResponse(), authentication);
            assertThat(response.getStatusCode().value()).as(id + " relays the Domain status").isEqualTo(status);
            domain.verify();
        }
        assertThat(proxied).isGreaterThan(50);
    }

    @Test void cloudSignInActionsMatchTheGatewayCallSites() throws Exception {
        var contract = contract();
        var settings = OAuthSettings.from(new GatewayDeploymentTest().production());
        assertThat(settings.cloud()).isTrue();
        // Browser routes of CloudAccountController become Domain actions by their last segment (two renames); the
        // security handlers and the sign-out call their action by name.
        var expected = new TreeSet<String>();
        String controller = source(MAIN.resolve("com/lookahead/learning/content/gateway/CloudAccountController.java"));
        for (String annotation : List.of("GetMapping", "PostMapping")) {
            Matcher mapping = Pattern.compile("@" + annotation + "\\(\\{([^}]*)\\}\\)").matcher(controller);
            assertThat(mapping.find()).as(annotation + " routes").isTrue();
            Matcher route = Pattern.compile("\"(/api/v1/[^\"]+)\"").matcher(mapping.group(1));
            while (route.find()) {
                String action = route.group(1).substring(route.group(1).lastIndexOf('/') + 1);
                if (action.equals("sign-ins")) action = "inventory";
                if (action.equals("sign-in-challenge")) action = "challenge";
                expected.add((annotation.equals("GetMapping") ? "GET " : "POST ") + action);
            }
        }
        for (Path file : mainSources()) {
            Matcher call = Pattern.compile("\\.call\\(\"([a-z-]+)\"").matcher(source(file));
            while (call.find()) expected.add("POST " + call.group(1));
        }
        var listed = new TreeSet<String>();
        for (JsonNode entry : contract.path("calls")) {
            String path = entry.path("path").asString();
            if (!path.startsWith("/internal/v1/cloud-sign-ins/")) continue;
            String action = path.substring("/internal/v1/cloud-sign-ins/".length());
            listed.add(entry.path("method").asString() + " " + action);
            boolean get = entry.path("method").asString().equals("GET");
            var body = new LinkedHashMap<String, Object>();
            if (!get) entry.path("exampleBody").properties().forEach(property -> body.put(property.getKey(), property.getValue().isNull() ? null : property.getValue().asString()));
            var builder = RestClient.builder();
            var domain = MockRestServiceServer.bindTo(builder).build();
            var data = new StringBuilder("{\"data\":{");
            var fields = new ArrayList<String>();
            for (String field : strings(entry.path("reads"))) fields.add("\"" + field.substring("data.".length()) + "\":\"synthetic\"");
            data.append(String.join(",", fields)).append("},\"timestamp\":\"2026-10-31T00:00:00Z\"}");
            domain.expect(requestTo(settings.domainApiUpstream() + path)).andExpect(method(get ? HttpMethod.GET : HttpMethod.POST))
                    .andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body(data.toString()));
            var result = new CloudGatewaySessions(settings, builder.build()).call(action, "synthetic-token", new MockHttpServletRequest(), get ? null : body);
            assertThat(result.status()).as(entry.path("id").asString()).isEqualTo(200);
            for (String field : strings(entry.path("reads")))
                assertThat(result.data().path(field.substring("data.".length())).asString()).as(field).isEqualTo("synthetic");
            domain.verify();
        }
        assertThat(listed).isEqualTo(expected);
    }

    @Test void authorPreviewAccessCheckUsesTheContractPathAndStatus() throws Exception {
        var contract = contract();
        JsonNode entry = contract.path("calls").valueStream().filter(call -> call.path("id").asString().equals("author-preview-access")).findFirst().orElseThrow();
        assertThat(strings(entry.path("callers"))).contains("AuthorPreviewProxy.fetch");
        var builder = RestClient.builder();
        var domain = MockRestServiceServer.bindTo(builder).build();
        domain.expect(requestTo(AuthorPreviewSettingsTest.OAUTH.domainApiUpstream() + entry.path("example").asString()))
                .andExpect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.valueOf(entry.path("statuses").get(0).asInt())));
        domain.expect(requestTo("http://127.0.0.1:4315/preview-directory/manifest.json"))
                .andRespond(withStatus(HttpStatus.OK).contentType(MediaType.APPLICATION_JSON).body("{}"));
        var proxy = new AuthorPreviewProxy(new AuthorPreviewSettings(URI.create("http://127.0.0.1:4315"), AuthorPreviewSettingsTest.SOURCE_SECRET),
                AuthorPreviewSettingsTest.OAUTH, builder.build());
        assertThat(proxy.fetch("GET", AuthorPreviewPath.PREFIX + "preview-directory/manifest.json", null, "synthetic-token").getStatusCode().value()).isEqualTo(200);
        domain.verify();
    }

    @Test void everyDomainPathLiteralInTheGatewaySourceIsCoveredByTheContract() throws Exception {
        var contract = contract();
        var examples = new ArrayList<String>();
        for (JsonNode entry : entries(contract, "calls", "forwardedWithoutProvider")) examples.add(entry.path("example").asString());
        var uncovered = new TreeSet<String>();
        int literals = 0;
        for (Path file : mainSources()) {
            String text = source(file);
            if (!text.contains("domainApiUpstream")) continue; // Identity-bound and browser-facing routes live elsewhere
            Matcher literal = DOMAIN_LITERAL.matcher(text);
            while (literal.find()) {
                literals++;
                String fragment = literal.group(1).replace("**", "");
                Pattern prefix;
                try { prefix = Pattern.compile("^" + fragment); } catch (PatternSyntaxException invalid) { prefix = Pattern.compile("^" + Pattern.quote(fragment)); }
                final Pattern matcher = prefix;
                if (examples.stream().noneMatch(example -> matcher.matcher(example).find())) uncovered.add(file.getFileName() + ": " + literal.group(1));
            }
        }
        assertThat(literals).isGreaterThan(30);
        assertThat(uncovered).as("Domain path literals missing from contracts/domain-api-v1.json").isEmpty();
    }

    @Test void webPathsAreExactlyTheDestinationsTheGatewaySendsBrowsersTo() throws Exception {
        var webPaths = strings(contract().path("webPaths"));
        var expected = new TreeSet<>(List.of("/", "/index.html"));
        for (Path file : mainSources()) {
            Matcher redirect = FRONTEND_LITERAL.matcher(source(file));
            while (redirect.find()) if (DevWebProxy.safePath(redirect.group(1))) expected.add(redirect.group(1));
        }
        String configuration = source(MAIN.resolve("com/lookahead/learning/content/gateway/GatewayConfiguration.java"));
        int start = configuration.indexOf("public static String safeReturn(");
        String body = configuration.substring(start, configuration.indexOf("\n    }", start));
        Matcher exact = Pattern.compile("path\\.equals\\(\"(/[^\"]*)\"\\)").matcher(body);
        while (exact.find()) expected.add(exact.group(1));
        Matcher roots = Pattern.compile("\\^/\\(\\?:([a-z|-]+)\\)").matcher(body);
        assertThat(roots.find()).isTrue();
        for (String root : roots.group(1).split("\\|")) expected.add("/" + root);
        assertThat(new TreeSet<>(webPaths)).isEqualTo(expected);
        for (String path : webPaths) {
            assertThat(DevWebProxy.safePath(path)).as(path + " is forwarded to Web").isTrue();
            assertThat(path.startsWith("/sign-in") || path.equals("/index.html") || GatewayConfiguration.safeReturn(path).equals(path)).as(path).isTrue();
        }
    }
}
