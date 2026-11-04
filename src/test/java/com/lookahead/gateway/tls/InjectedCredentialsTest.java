package com.lookahead.gateway.tls;

import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.env.MapPropertySource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.ssl.SslBundles;
import static org.junit.jupiter.api.Assertions.*;

class InjectedCredentialsTest {
    @TempDir Path directory;
    String originalTrust;
    void command(String... arguments) throws Exception {
        var command = new ArrayList<String>(); command.add("openssl"); command.addAll(List.of(arguments));
        var process = new ProcessBuilder(command).directory(directory.toFile())
            .redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(process.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, process.exitValue());
    }
    String text(String name) throws Exception { return Files.readString(directory.resolve(name)); }
    void leaf(String name, String subject, String san, String purpose, String days, String key) throws Exception {
        command("req", "-new", "-key", key, "-out", name+".csr", "-subj", subject);
        Files.writeString(directory.resolve("extensions"), "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:"+san+"\nextendedKeyUsage="+purpose+"\n");
        var arguments=new ArrayList<>(List.of("x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", name+".pem", "-extfile", "extensions"));
        if (days.equals("expired") || days.equals("future")) {
            // `ca` explicit validity dates work on CI's OpenSSL 3.0 as well as newer versions.
            Files.writeString(directory.resolve("index"), "");
            Files.writeString(directory.resolve("serial"), "01\n");
            Files.writeString(directory.resolve("ca.conf"), """
                [ca]
                default_ca=fixture
                [fixture]
                database=index
                serial=serial
                new_certs_dir=.
                certificate=ca.pem
                private_key=ca.key
                default_md=sha256
                policy=subject
                [subject]
                commonName=supplied
                """);
            arguments = new ArrayList<>(List.of("ca", "-batch", "-notext", "-config", "ca.conf",
                "-in", name+".csr", "-out", name+".pem", "-extfile", "extensions", "-startdate",
                days.equals("expired") ? "20000101000000Z" : "20990101000000Z", "-enddate",
                days.equals("expired") ? "20010101000000Z" : "20990103000000Z"));
        } else arguments.addAll(List.of("-days",days));
        command(arguments.toArray(String[]::new));
    }
    @BeforeEach void fixtures() throws Exception {
        command("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "5", "-subj", "/CN=Synthetic root", "-addext", "basicConstraints=critical,CA:TRUE");
        command("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "server.key");
        command("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "client.key");
        leaf("server", "/CN=dev.example.com", "dev.example.com", "serverAuth", "3", "server.key");
        leaf("client", "/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "3", "client.key");
        originalTrust=System.getProperty("javax.net.ssl.trustStore");
        KeyStore store=KeyStore.getInstance("JKS"); store.load(null, null);
        store.setCertificateEntry("synthetic", InjectedCredentialValidator.certificates(text("ca.pem")).getFirst());
        try (var output=Files.newOutputStream(directory.resolve("trust.jks"))) { store.store(output, "changeit".toCharArray()); }
        System.setProperty("javax.net.ssl.trustStore", directory.resolve("trust.jks").toString());
    }
    @AfterEach void restoreTrust() {
        if(originalTrust==null)System.clearProperty("javax.net.ssl.trustStore");else System.setProperty("javax.net.ssl.trustStore",originalTrust);
    }
    Map<String,String> input() throws Exception {
        return new LinkedHashMap<>(Map.ofEntries(
            Map.entry("LOOKAHEAD_TLS_SCHEMA","lookahead-tls/v1"), Map.entry("LOOKAHEAD_TLS_SERVER_NAME","dev.example.com"),
            Map.entry("LOOKAHEAD_TLS_SERVER_CERTIFICATE",text("server.pem")),Map.entry("LOOKAHEAD_TLS_SERVER_KEY",text("server.key")),
            Map.entry("LOOKAHEAD_TLS_TRUST",text("ca.pem")),Map.entry("LOOKAHEAD_TLS_CLIENT_CERTIFICATE",text("client.pem")),Map.entry("LOOKAHEAD_TLS_CLIENT_KEY",text("client.key")),
            Map.entry("LOOKAHEAD_DOMAIN_GATEWAY_SECRET","synthetic-gateway-secret"),Map.entry("APP_OAUTH_CLIENT_ID","SyntheticClient1"),
            Map.entry("LOOKAHEAD_GATEWAY_CLIENT_SECRET","synthetic-oauth-secret"),Map.entry("LOOKAHEAD_ADMISSION_CLIENT_ID","SyntheticClient2"),
            Map.entry("LOOKAHEAD_ADMISSION_CLIENT_SECRET","synthetic-admission-secret"),Map.entry("LOOKAHEAD_DOMAIN_DB_PASSWORD","a".repeat(48))));
    }
    @Test void positiveBundlesAreConsumedBySpringWithoutFiles() throws Exception {
        for(String service:List.of("gateway","domain")) {
            var properties=InjectedCredentialValidator.properties(input(), service);
            new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(SslAutoConfiguration.class))
                .withInitializer(c->c.getEnvironment().getPropertySources().addFirst(new MapPropertySource("synthetic",properties)))
                .run(c->{ assertNull(c.getStartupFailure()); var bundles=c.getBean(SslBundles.class);
                    assertNotNull(bundles.getBundle("serving").createSslContext());
                    if(service.equals("gateway")) assertNotNull(bundles.getBundle("internal").createSslContext()); });
        }
    }
    @Test void initializerRunsOnlyOnCloudProfileAndOverridesUnvalidatedConfiguration() throws Exception {
        try(var context=new GenericApplicationContext()) {
            var initializer=new InjectedCredentials();initializer.initialize(context);
            assertFalse(context.getEnvironment().getPropertySources().contains("validatedInjectedCredentials"));
            context.getEnvironment().setActiveProfiles("lower-cost-dev");
            var values=new HashMap<String,Object>(input());values.put("spring.ssl.bundle.pem.serving.keystore.private-key","invalid override");
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("synthetic",values));
            initializer.initialize(context);
            assertEquals(text("server.key"),context.getEnvironment().getProperty("spring.ssl.bundle.pem.serving.keystore.private-key"));
        }
        assertTrue(new String(getClass().getResourceAsStream("/META-INF/spring.factories").readAllBytes()).contains(InjectedCredentials.class.getName()));
    }
    @Test void unresolvedEnvironmentPlaceholdersDoNotLeakFromStartup() {
        try(var context=new GenericApplicationContext()) {
            context.getEnvironment().setActiveProfiles("lower-cost-dev");
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("synthetic",Map.of("LOOKAHEAD_TLS_SCHEMA","${private-marker}")));
            var failure=assertThrows(IllegalStateException.class,()->new InjectedCredentials().initialize(context));
            assertEquals("Injected credential validation failed; application startup denied",failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    @Test void missingInputsRejectBeforeContextRefreshWithoutLeakingValues() throws Exception {
        for(String service:List.of("gateway","domain")) {
            var keys=new ArrayList<>(input().keySet());
            if(service.equals("domain"))keys.removeAll(List.of("LOOKAHEAD_TLS_CLIENT_CERTIFICATE","LOOKAHEAD_TLS_CLIENT_KEY","APP_OAUTH_CLIENT_ID","LOOKAHEAD_GATEWAY_CLIENT_SECRET","LOOKAHEAD_ADMISSION_CLIENT_ID","LOOKAHEAD_ADMISSION_CLIENT_SECRET"));
            else keys.remove("LOOKAHEAD_DOMAIN_DB_PASSWORD");
            for(String key:keys) {
                var values=input();values.remove(key);
                var failure=assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,service),key);
                assertEquals("Injected credential validation failed; application startup denied",failure.getMessage());assertNull(failure.getCause());
            }
        }
    }
    @Test void wrongHostnamePurposeKeyAndTrustReject() throws Exception {
        for(var entry:Map.of("LOOKAHEAD_TLS_SERVER_NAME","wrong.example.com","LOOKAHEAD_TLS_SERVER_KEY",text("ca.key"),"LOOKAHEAD_TLS_TRUST",text("server.pem"),"LOOKAHEAD_TLS_SERVER_CERTIFICATE",text("client.pem"),"LOOKAHEAD_TLS_SCHEMA","wrong").entrySet()) {
            var values=input();values.put(entry.getKey(),entry.getValue());
            assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        }
        command("req","-x509","-newkey","rsa:2048","-nodes","-keyout","other.key","-out","other.pem","-days","5","-subj","/CN=Untrusted root","-addext","basicConstraints=critical,CA:TRUE");
        var values=input();values.put("LOOKAHEAD_TLS_TRUST",text("other.pem"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
    }
    @Test void shortLifetimeExpiredAndWrongClientSubjectReject() throws Exception {
        for(String days:List.of("1","expired","future")) {
            leaf("short", "/CN=dev.example.com", "dev.example.com", "serverAuth", days, "server.key");
            var values=input();values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE",text("short.pem"));
            assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        }
        leaf("extra", "/O=Unexpected/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "3", "client.key");
        var values=input();values.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE",text("extra.pem"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"gateway"));
    }
    @Test void wrongExtendedUsageAndUnsupportedKeyFormatRejectIndependently() throws Exception {
        leaf("purpose", "/CN=dev.example.com", "dev.example.com", "clientAuth", "3", "server.key");
        var values=input();values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE",text("purpose.pem"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        var badKey=input();badKey.put("LOOKAHEAD_TLS_SERVER_KEY","-----BEGIN RSA PRIVATE KEY-----\ninvalid");
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(badKey,"domain"));
    }

    @Test void privateKeyEnvelopeMustBeCompleteAndContainOnlyOnePkcs8Key() throws Exception {
        String key = text("server.key");
        for (String invalid : List.of(
                key.replaceAll("-{5}END PRIVATE KEY-{5}", ""),
                key.replace("END PRIVATE", "END RSA PRIVATE"),
                key.replace("BEGIN PRIVATE", "BEGIN ENCRYPTED PRIVATE"),
                key.replaceFirst("\\R", ""), key + key, key + "trailing-source", "prefix" + key)) {
            var values = input(); values.put("LOOKAHEAD_TLS_SERVER_KEY", invalid);
            var failure = assertThrows(IllegalStateException.class,
                    () -> InjectedCredentialValidator.properties(values, "domain"));
            assertEquals("Injected credential validation failed; application startup denied", failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    @Test void duplicateGatewayKeysAndCaLeafReject() throws Exception {
        leaf("same", "/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "3", "server.key");
        var values=input();values.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE",text("same.pem"));values.put("LOOKAHEAD_TLS_CLIENT_KEY",text("server.key"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"gateway"));
        values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE",text("ca.pem"));values.put("LOOKAHEAD_TLS_SERVER_KEY",text("ca.key"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"gateway"));
    }
    @Test void scalarAndMalformedPemBoundaries() throws Exception {
        for(String scalar:List.of("short","a".repeat(4097),"synthetic-secret\nvalue")) {
            var values=input();values.put("LOOKAHEAD_DOMAIN_GATEWAY_SECRET",scalar);
            assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        }
        for(String pem:List.of("", "file:/tmp/forbidden", "x".repeat(65537), text("server.pem").repeat(9))) {
            var values=input();values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE",pem);
            assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        }
        for(String id:List.of("invalid-id","a".repeat(129)))assertThrows(IllegalArgumentException.class,()->InjectedCredentialValidator.clientId(id));
        var values=input();values.put("LOOKAHEAD_DOMAIN_DB_PASSWORD","wrongshape-but-long-enough");
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"domain"));
        assertThrows(IllegalStateException.class,()->InjectedCredentialValidator.properties(values,"web"));
    }

    // ----- DLV-969 (owner, 2026-11-04): a rejected credential is named in the log, its value never is -----

    /** Runs the validator and returns the one refusal line's setting and reason; the exception stays unchanged. */
    List<String> refusal(Map<String,String> values, String service) {
        try (var log = new com.lookahead.gateway.LogCapture("lookahead.lifecycle")) {
            var failure = assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.properties(values, service));
            assertEquals("Injected credential validation failed; application startup denied", failure.getMessage());
            assertNull(failure.getCause());
            assertEquals(1, log.lines().size());
            assertEquals(ch.qos.logback.classic.Level.WARN, log.last().getLevel());
            var secrets = new ArrayList<String>(List.of("BEGIN", "PRIVATE KEY", "synthetic-gateway-secret", "synthetic-oauth-secret", "synthetic-admission-secret",
                    "SyntheticClient1", "SyntheticClient2", "aaaaaaaaaaaaaaaa"));
            for (String value : values.values()) if (value != null && value.length() > 12) secrets.add(value.strip().substring(0, 12));
            secrets.remove("lookahead-tl");  // the schema's value is a fixed, public name
            // The message ends in "startup denied" on purpose: the deploy's log check fails a start on it.
            log.assertNothing(secrets.toArray(String[]::new));
            var pairs = com.lookahead.gateway.LogCapture.pairs(log.last());
            return List.of(pairs.stream().filter(p -> p.startsWith("setting=")).findFirst().orElseThrow().substring(8),
                    pairs.stream().filter(p -> p.startsWith("reason=")).findFirst().orElseThrow().substring(7));
        }
    }

    @Test void everyMissingInputIsNamed() throws Exception {
        for (String service : List.of("gateway", "domain")) {
            var keys = new ArrayList<>(input().keySet());
            if (service.equals("domain")) keys.removeAll(List.of("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "LOOKAHEAD_TLS_CLIENT_KEY", "APP_OAUTH_CLIENT_ID",
                    "LOOKAHEAD_GATEWAY_CLIENT_SECRET", "LOOKAHEAD_ADMISSION_CLIENT_ID", "LOOKAHEAD_ADMISSION_CLIENT_SECRET"));
            else keys.remove("LOOKAHEAD_DOMAIN_DB_PASSWORD");
            for (String key : keys) {
                var values = input(); values.remove(key);
                assertEquals(List.of("injected credential " + key, "MISSING"), refusal(values, service), service + " " + key);
            }
        }
        assertEquals(List.of("injected credential service", "UNKNOWN_SERVICE"), refusal(input(), "web"));
    }

    @Test void eachRejectionSaysWhichInputAndWhy() throws Exception {
        record Case(String key, String value, String service, String setting, String reason) { }
        command("req","-x509","-newkey","rsa:2048","-nodes","-keyout","other.key","-out","other.pem","-days","5","-subj","/CN=Untrusted root","-addext","basicConstraints=critical,CA:TRUE");
        leaf("purpose", "/CN=dev.example.com", "dev.example.com", "clientAuth", "3", "server.key");
        leaf("short", "/CN=dev.example.com", "dev.example.com", "serverAuth", "1", "server.key");
        var cases = List.of(
            new Case("LOOKAHEAD_TLS_SCHEMA", "lookahead-tls/v0", "gateway", "LOOKAHEAD_TLS_SCHEMA", "UNSUPPORTED_SCHEMA"),
            new Case("LOOKAHEAD_TLS_SERVER_NAME", "wrong.example.com", "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "NAME_NOT_IN_SUBJECT_ALTERNATIVE_NAMES"),
            new Case("LOOKAHEAD_TLS_SERVER_NAME", "Not A Name", "domain", "LOOKAHEAD_TLS_SERVER_NAME", "NOT_A_LOWER_CASE_HOST_NAME"),
            new Case("LOOKAHEAD_TLS_SERVER_KEY", text("ca.key"), "domain", "LOOKAHEAD_TLS_SERVER_KEY", "KEY_DOES_NOT_MATCH_CERTIFICATE"),
            new Case("LOOKAHEAD_TLS_SERVER_KEY", text("client.key"), "domain", "LOOKAHEAD_TLS_SERVER_KEY", "KEY_UNREADABLE"),
            new Case("LOOKAHEAD_TLS_SERVER_KEY", "-----BEGIN RSA PRIVATE KEY-----\ninvalid", "domain", "LOOKAHEAD_TLS_SERVER_KEY", "NOT_ONE_PKCS8_PEM_BLOCK"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("ca.pem"), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "LEAF_IS_A_CA_CERTIFICATE"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("purpose.pem"), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "NOT_FOR_SERVER_AUTHENTICATION"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("short.pem"), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "EXPIRES_WITHIN_ONE_DAY"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", "file:/tmp/forbidden", "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "CERTIFICATE_UNREADABLE"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", "x".repeat(65537), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "LONGER_THAN_64_KB"),
            new Case("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("server.pem").repeat(9), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "MORE_THAN_8_CERTIFICATES"),
            new Case("LOOKAHEAD_TLS_TRUST", text("server.pem"), "domain", "LOOKAHEAD_TLS_TRUST", "NOT_A_SELF_SIGNED_CA"),
            new Case("LOOKAHEAD_TLS_TRUST", text("other.pem"), "domain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE (its chain to LOOKAHEAD_TLS_TRUST)", "CHAIN_NOT_TRUSTED"),
            new Case("LOOKAHEAD_TLS_TRUST", text("other.pem"), "gateway", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE (its chain to LOOKAHEAD_TLS_TRUST)", "CHAIN_NOT_TRUSTED"),
            new Case("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "short", "domain", "LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "LENGTH_OUTSIDE_16_TO_4096"),
            new Case("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-secret\nvalue", "domain", "LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "CONTROL_CHARACTERS"),
            new Case("APP_OAUTH_CLIENT_ID", "invalid-id", "gateway", "APP_OAUTH_CLIENT_ID", "NOT_1_TO_128_ALPHANUMERIC_CHARACTERS"),
            new Case("LOOKAHEAD_DOMAIN_DB_PASSWORD", "wrongshape-but-long-enough", "domain", "LOOKAHEAD_DOMAIN_DB_PASSWORD", "NOT_48_ALPHANUMERIC_CHARACTERS"));
        for (var test : cases) {
            var values = input(); values.put(test.key(), test.value());
            assertEquals(List.of("injected credential " + test.setting(), test.reason()), refusal(values, test.service()), test.toString().substring(0, 80));
        }
        // The client certificate must not reuse the server's key, and its subject must be exactly the Gateway name.
        leaf("same", "/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "3", "server.key");
        var same = input(); same.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("same.pem")); same.put("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key"));
        assertEquals(List.of("injected credential LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "SAME_KEY_AS_SERVER_CERTIFICATE"), refusal(same, "gateway"));
        leaf("extra", "/O=Unexpected/CN=gateway.lookahead-dev.internal", "gateway.lookahead-dev.internal", "clientAuth", "3", "client.key");
        var extra = input(); extra.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("extra.pem"));
        assertEquals(List.of("injected credential LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "CLIENT_SUBJECT_NOT_EXACTLY_CN"), refusal(extra, "gateway"));
        for (String days : List.of("expired", "future")) {
            leaf("dated", "/CN=dev.example.com", "dev.example.com", "serverAuth", days, "server.key");
            var dated = input(); dated.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("dated.pem"));
            assertEquals(List.of("injected credential LOOKAHEAD_TLS_SERVER_CERTIFICATE", days.equals("expired") ? "CERTIFICATE_EXPIRED" : "CERTIFICATE_NOT_YET_VALID"),
                    refusal(dated, "domain"));
        }
    }

    @Test void anUnreadableVariableIsNamedWithoutItsValue() {
        try (var log = new com.lookahead.gateway.LogCapture("lookahead.lifecycle"); var context = new GenericApplicationContext()) {
            context.getEnvironment().setActiveProfiles("lower-cost-dev");
            context.getEnvironment().getPropertySources().addFirst(new MapPropertySource("synthetic", Map.of("LOOKAHEAD_TLS_TRUST", "${private-marker}")));
            var failure = assertThrows(IllegalStateException.class, () -> new InjectedCredentials().initialize(context));
            assertEquals("Injected credential validation failed; application startup denied", failure.getMessage());
            assertTrue(com.lookahead.gateway.LogCapture.pairs(log.last()).containsAll(List.of("setting=injected credential LOOKAHEAD_TLS_TRUST",
                    "reason=UNRESOLVED_PLACEHOLDER")));
            log.assertNothing("private-marker");
        }
        assertEquals("InvalidAlgorithmParameterException", InjectedCredentialValidator.reason(new java.security.InvalidAlgorithmParameterException()));
        assertEquals("CHAIN_NOT_TRUSTED", InjectedCredentialValidator.reason(new java.security.cert.CertPathBuilderException()));
        assertEquals("KEY_DOES_NOT_MATCH_CERTIFICATE", InjectedCredentialValidator.reason(new java.security.SignatureException()));
        assertEquals("CERTIFICATE_UNREADABLE", InjectedCredentialValidator.reason(new java.security.cert.CertificateException()));
    }
}
