package com.lookahead.gateway;

import java.io.ByteArrayInputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import static org.junit.jupiter.api.Assertions.*;

/**
 * DLV-914: boots the real {@code lower-cost-dev} profile the way the DEV task definition does, with synthetic
 * injected credentials and the exact Infra environment names. Proves startup validation, TLS-only public
 * serving, the loopback management port the ECS probe uses, and the admission gate. No AWS call is made:
 * every route exercised stops before a Cognito or DynamoDB request. Synthetic values only.
 */
class LowerCostDevRuntimeIntegrationTest {
    @TempDir Path directory;
    private String originalTrust;
    private ConfigurableApplicationContext context;
    private SSLSocketFactory synthetic;

    record Reply(int status, String location, String contentType, String policy, String body) {}

    private void command(String... arguments) throws Exception {
        var command = new ArrayList<String>(); command.add("openssl"); command.addAll(List.of(arguments));
        var process = new ProcessBuilder(command).directory(directory.toFile())
                .redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, process.exitValue());
    }

    private String text(String name) throws Exception { return Files.readString(directory.resolve(name)); }

    private void leaf(String name, String subject, String san, String purpose, String key) throws Exception {
        command("req", "-new", "-key", key, "-out", name + ".csr", "-subj", subject);
        Files.writeString(directory.resolve("extensions"), "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:" + san + "\nextendedKeyUsage=" + purpose + "\n");
        command("x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out", name + ".pem", "-extfile", "extensions", "-days", "3");
    }

    @BeforeEach void fixtures() throws Exception {
        command("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "5", "-subj", "/CN=Synthetic root", "-addext", "basicConstraints=critical,CA:TRUE");
        command("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "server.key");
        command("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "client.key");
        // The public server name is whatever LOOKAHEAD_TLS_SERVER_NAME says; localhost lets the test verify the hostname.
        leaf("server", "/CN=localhost", "localhost", "serverAuth", "server.key");
        leaf("client", "/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "client.key");
        var root = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(text("ca.pem").getBytes(StandardCharsets.US_ASCII)));
        KeyStore store = KeyStore.getInstance("JKS"); store.load(null, null); store.setCertificateEntry("synthetic", root);
        try (var output = Files.newOutputStream(directory.resolve("trust.jks"))) { store.store(output, "changeit".toCharArray()); }
        // The Gateway's public certificate chain is checked against platform trust; a synthetic root is only trusted here.
        originalTrust = System.getProperty("javax.net.ssl.trustStore");
        System.setProperty("javax.net.ssl.trustStore", directory.resolve("trust.jks").toString());
        var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trust.init(store);
        var ssl = SSLContext.getInstance("TLS"); ssl.init(null, trust.getTrustManagers(), null); synthetic = ssl.getSocketFactory();
    }

    @AfterEach void shutdown() {
        if (context != null) context.close();
        if (originalTrust == null) System.clearProperty("javax.net.ssl.trustStore"); else System.setProperty("javax.net.ssl.trustStore", originalTrust);
    }

    /** Exactly the names Infra's generated DEV task definition sets, plus the ECS-injected secret names. */
    private Map<String, String> taskDefinition() throws Exception {
        var env = new LinkedHashMap<String, String>();
        env.put("server.port", "0"); env.put("management.server.port", "0");
        env.put("LOOKAHEAD_ENVIRONMENT", "dev"); env.put("LOOKAHEAD_RUNTIME_MODE", "lower-cost-dev");
        env.put("LOOKAHEAD_TLS_SERVER_NAME", "localhost"); env.put("spring.profiles.active", "lower-cost-dev");
        env.put("AWS_REGION", "us-east-2");
        env.put("LOOKAHEAD_COGNITO_ISSUER", "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_Example");
        env.put("LOOKAHEAD_COGNITO_SCOPE_PREFIX", "lookahead-dev");
        env.put("LOOKAHEAD_FRONTEND_ORIGIN", "https://dev.example.test");
        env.put("LOOKAHEAD_COGNITO_MANAGED_LOGIN", "https://dev-example.auth.us-east-2.amazoncognito.com");
        env.put("LOOKAHEAD_DEV_STATE_TABLE", "lookahead-dev-operations");
        // DLV-969: the four LOOKAHEAD_ADMISSION_* values stay in the task definition until phase D; the Gateway no longer reads the pool.
        env.put("LOOKAHEAD_ADMISSION_POOL_ID", "us-east-2_Admission1");
        env.put("LOOKAHEAD_ADMISSION_MANAGED_LOGIN", "https://admission-example.auth.us-east-2.amazoncognito.com");
        env.put("LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.lookahead-dev.internal:8443");
        env.put("LOOKAHEAD_WEB_UPSTREAM", "https://web.lookahead-dev.internal:8443");
        env.put("LOOKAHEAD_DOMAIN_TRANSPORT", "application-mtls");
        env.put("APP_AUTHOR_PREVIEWS_ENABLED", "false");
        env.put("LOOKAHEAD_TLS_SCHEMA", "lookahead-tls/v1");
        env.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("server.pem")); env.put("LOOKAHEAD_TLS_SERVER_KEY", text("server.key"));
        env.put("LOOKAHEAD_TLS_TRUST", text("ca.pem"));
        env.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("client.pem")); env.put("LOOKAHEAD_TLS_CLIENT_KEY", text("client.key"));
        env.put("APP_OAUTH_CLIENT_ID", "syntheticlearnerclient1");
        env.put("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "synthetic-learner-client-secret-never-deployed");
        env.put("LOOKAHEAD_ADMISSION_CLIENT_ID", "syntheticadmissionclient1");
        env.put("LOOKAHEAD_ADMISSION_CLIENT_SECRET", "synthetic-admission-client-secret-never-deployed");
        env.put("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-domain-gateway-secret-never-deployed");
        return env;
    }

    private ConfigurableApplicationContext start(Map<String, String> env) {
        var application = new SpringApplication(GatewayApplication.class);
        application.setAdditionalProfiles("gateway");
        return application.run(env.entrySet().stream().map(e -> "--" + e.getKey() + "=" + e.getValue()).toArray(String[]::new));
    }

    private Reply call(String method, String url, Map<String, String> headers) throws Exception {
        var connection = (HttpURLConnection) URI.create(url).toURL().openConnection();
        if (connection instanceof HttpsURLConnection https) https.setSSLSocketFactory(synthetic);
        connection.setInstanceFollowRedirects(false); connection.setRequestMethod(method);
        connection.setConnectTimeout(3000); connection.setReadTimeout(5000);
        headers.forEach(connection::setRequestProperty);
        if (method.equals("POST")) { connection.setDoOutput(true); connection.getOutputStream().close(); }
        int status = connection.getResponseCode();
        var stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream();
        String body = stream == null ? "" : new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        return new Reply(status, connection.getHeaderField("Location"), connection.getContentType(),
                connection.getHeaderField("Content-Security-Policy"), body);
    }

    @Test void devTaskDefinitionBootsServesTlsOnlyAndGatesEverythingBehindAdmission() throws Exception {
        context = start(taskDefinition());
        int port = context.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
        int management = context.getEnvironment().getRequiredProperty("local.management.port", Integer.class);
        assertNotEquals(port, management);
        assertTrue(context.getEnvironment().getPropertySources().contains("validatedInjectedCredentials"), "spring.factories initializer ran");
        String base = "https://localhost:" + port;

        // The ECS probe target: loopback management readiness with the exact body ContainerHealthcheck accepts.
        var readiness = call("GET", "http://127.0.0.1:" + management + "/actuator/health/readiness", Map.of());
        assertEquals(200, readiness.status()); assertTrue(readiness.body().matches("\\s*\\{\\s*\"status\"\\s*:\\s*\"UP\"\\s*}\\s*"), readiness.body());
        var info = call("GET", "http://127.0.0.1:" + management + "/actuator/info", Map.of());
        assertEquals(200, info.status()); assertTrue(info.body().contains("releaseTag") && info.body().contains("sourceRevision"));
        assertNotEquals(200, call("GET", "http://127.0.0.1:" + management + "/actuator/env", Map.of()).status());

        // The public port is TLS with the injected certificate; plaintext is refused.
        var https = (HttpsURLConnection) URI.create(base + "/dev/access").toURL().openConnection();
        https.setSSLSocketFactory(synthetic); https.setInstanceFollowRedirects(false); https.connect();
        assertEquals("CN=localhost", ((X509Certificate) https.getServerCertificates()[0]).getSubjectX500Principal().getName());
        https.disconnect();
        assertEquals(400, call("GET", "http://localhost:" + port + "/dev/access", Map.of()).status());

        // Admission gate: browser navigation goes to the access page; APIs, content and release metadata never leak.
        var shell = call("GET", base + "/", Map.of());
        assertEquals(302, shell.status()); assertTrue(shell.location().endsWith("/dev/access"), shell.location());
        for (String path : List.of("/actuator/info", "/actuator/health/readiness", "/learn")) {
            var reply = call("GET", base + path, Map.of());
            assertEquals(302, reply.status(), path); assertTrue(reply.location().endsWith("/dev/access"), path);
        }
        for (String path : List.of("/dev/session", "/bff/logout/complete", "/bff/api/v1/plans", "/api/v1/auth/me", "/content/lesson.json")) {
            var reply = call("GET", base + path, Map.of());
            assertEquals(401, reply.status(), path); assertTrue(reply.contentType().startsWith("application/json"), path);
            assertTrue(reply.body().contains("DEV_ADMISSION_REQUIRED"), path);
        }
        assertEquals(401, call("POST", base + "/bff/api/v1/plans", Map.of()).status());

        // DLV-969: the access page starts the Look Ahead sign-in; its three routes run unadmitted against the learner client only.
        var access = call("GET", base + "/dev/access", Map.of());
        assertEquals(200, access.status()); assertTrue(access.contentType().startsWith("text/html"));
        assertTrue(access.body().contains("href=\"/bff/login?provider=password&amp;returnTo=%2F\"")); assertFalse(access.body().contains("/dev/oauth2/"));
        // Google stays hidden until LOOKAHEAD_GOOGLE_SIGN_IN is set, and asking for it anyway falls back to Cognito's page.
        assertFalse(access.body().contains("provider=google"));
        assertTrue(access.policy().contains("default-src 'none'"));
        var login = call("GET", base + "/bff/login?returnTo=%2F", Map.of());
        assertEquals(302, login.status()); assertEquals("https://dev.example.test/oauth2/authorization/lookahead", login.location());
        var authorize = call("GET", base + "/oauth2/authorization/lookahead", Map.of());
        assertEquals(302, authorize.status());
        assertTrue(authorize.location().startsWith("https://dev-example.auth.us-east-2.amazoncognito.com/oauth2/authorize?"), authorize.location());
        for (String expected : List.of("client_id=syntheticlearnerclient1", "code_challenge_method=S256", "prompt=login",
                "redirect_uri=https://dev.example.test/login/oauth2/code/lookahead"))
            assertTrue(authorize.location().contains(expected), expected);
        assertFalse(authorize.location().contains("synthetic-learner-client-secret")); assertFalse(authorize.location().contains("admission"));
        assertFalse(authorize.location().contains("identity_provider"));
        // DLV-969: the password button skips straight to Cognito's own password form.
        var password = call("GET", base + "/bff/login?provider=password&returnTo=%2F", Map.of());
        assertEquals(302, password.status()); assertEquals("https://dev.example.test/oauth2/authorization/lookahead?provider=password", password.location());
        var passwordAuthorize = call("GET", base + "/oauth2/authorization/lookahead?provider=password", Map.of());
        assertEquals(302, passwordAuthorize.status());
        assertTrue(passwordAuthorize.location().contains("identity_provider=COGNITO"), passwordAuthorize.location());
        assertTrue(passwordAuthorize.location().contains("prompt=login"), passwordAuthorize.location());
        var googleOff = call("GET", base + "/oauth2/authorization/lookahead?provider=google", Map.of());
        assertEquals(302, googleOff.status()); assertFalse(googleOff.location().contains("identity_provider"), googleOff.location());
        var unknown = call("GET", base + "/bff/login?provider=facebook&returnTo=%2F", Map.of());
        assertEquals("https://dev.example.test/oauth2/authorization/lookahead", unknown.location());
        var removed = call("GET", base + "/dev/oauth2/authorization/admission", Map.of());
        assertEquals(401, removed.status()); assertTrue(removed.body().contains("DEV_ADMISSION_REQUIRED"));
        var complete = call("GET", base + "/dev/leave/complete", Map.of());
        assertEquals(302, complete.status()); assertTrue(complete.location().endsWith("/dev/access"), complete.location());

        // Leave DEV needs the admission chain's CSRF token under the header name the Web shell sends.
        var csrf = call("GET", base + "/dev/csrf", Map.of());
        assertEquals(200, csrf.status()); assertTrue(csrf.body().contains("\"headerName\":\"X-CSRF-TOKEN\""));
        assertEquals(403, call("POST", base + "/dev/leave", Map.of()).status());
    }

    @Test void slotUpstreamOrMissingWebUpstreamDeniesStartup() throws Exception {
        // DLV-968 S3: the task definition names both stable upstreams; a release slot variable is no longer read.
        var noWeb = taskDefinition(); noWeb.remove("LOOKAHEAD_WEB_UPSTREAM"); noWeb.put("LOOKAHEAD_RELEASE_SLOT", "blue");
        assertThrows(Exception.class, () -> start(noWeb));
        var foreign = taskDefinition(); foreign.put("LOOKAHEAD_DOMAIN_UPSTREAM", "https://domain.attacker.test:8443");
        assertThrows(Exception.class, () -> start(foreign));
    }

    @Test void missingInjectedCredentialDeniesStartupWithoutLeakingValues() throws Exception {
        var env = taskDefinition(); env.remove("LOOKAHEAD_TLS_CLIENT_KEY");
        var failure = assertThrows(IllegalStateException.class, () -> start(env));
        assertEquals("Injected credential validation failed; application startup denied", failure.getMessage());
        assertNull(failure.getCause());
    }
}
