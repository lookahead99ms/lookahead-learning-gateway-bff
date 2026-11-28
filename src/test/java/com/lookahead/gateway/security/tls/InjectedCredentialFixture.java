package com.lookahead.gateway.security.tls;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

/**
 * The fixture InjectedCredentialInitializerTest and InjectedCredentialValidatorTest share: a
 * synthetic root, a server and a client certificate made with openssl in a temporary folder before
 * each test, the trust store set for the test, and the complete set of injected values. Not a test.
 */
abstract class InjectedCredentialFixture {
  @TempDir Path directory;
  String originalTrust;

  void command(String... arguments) throws Exception {
    var command = new ArrayList<String>();
    command.add("openssl");
    command.addAll(List.of(arguments));
    var process =
        new ProcessBuilder(command)
            .directory(directory.toFile())
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .start();
    assertTrue(process.waitFor(20, TimeUnit.SECONDS));
    assertEquals(0, process.exitValue());
  }

  String text(String name) throws Exception {
    return Files.readString(directory.resolve(name));
  }

  void leaf(String name, String subject, String san, String purpose, String days, String key)
      throws Exception {
    command("req", "-new", "-key", key, "-out", name + ".csr", "-subj", subject);
    Files.writeString(
        directory.resolve("extensions"),
        "basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:"
            + san
            + "\nextendedKeyUsage="
            + purpose
            + "\n");
    var arguments =
        new ArrayList<>(
            List.of(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                name + ".pem",
                "-extfile",
                "extensions"));
    if (days.equals("expired") || days.equals("future")) {
      // `ca` explicit validity dates work on CI's OpenSSL 3.0 as well as newer versions.
      Files.writeString(directory.resolve("index"), "");
      Files.writeString(directory.resolve("serial"), "01\n");
      Files.writeString(
          directory.resolve("ca.conf"),
          """
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
      arguments =
          new ArrayList<>(
              List.of(
                  "ca",
                  "-batch",
                  "-notext",
                  "-config",
                  "ca.conf",
                  "-in",
                  name + ".csr",
                  "-out",
                  name + ".pem",
                  "-extfile",
                  "extensions",
                  "-startdate",
                  days.equals("expired") ? "20000101000000Z" : "20990101000000Z",
                  "-enddate",
                  days.equals("expired") ? "20010101000000Z" : "20990103000000Z"));
    } else arguments.addAll(List.of("-days", days));
    command(arguments.toArray(String[]::new));
  }

  @BeforeEach
  void fixtures() throws Exception {
    command(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-days",
        "5",
        "-subj",
        "/CN=Synthetic root",
        "-addext",
        "basicConstraints=critical,CA:TRUE");
    command(
        "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "server.key");
    command(
        "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", "client.key");
    leaf("server", "/CN=dev.example.com", "dev.example.com", "serverAuth", "3", "server.key");
    leaf(
        "client",
        "/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "client.key");
    originalTrust = System.getProperty("javax.net.ssl.trustStore");
    KeyStore store = KeyStore.getInstance("JKS");
    store.load(null, null);
    store.setCertificateEntry(
        "synthetic", InjectedCredentialValidator.certificates(text("ca.pem")).getFirst());
    try (var output = Files.newOutputStream(directory.resolve("trust.jks"))) {
      store.store(output, "changeit".toCharArray());
    }
    System.setProperty("javax.net.ssl.trustStore", directory.resolve("trust.jks").toString());
  }

  @AfterEach
  void restoreTrust() {
    if (originalTrust == null) System.clearProperty("javax.net.ssl.trustStore");
    else System.setProperty("javax.net.ssl.trustStore", originalTrust);
  }

  Map<String, String> input() throws Exception {
    return new LinkedHashMap<>(
        Map.ofEntries(
            Map.entry("LOOKAHEAD_TLS_SCHEMA", "lookahead-tls/v1"),
            Map.entry("LOOKAHEAD_TLS_SERVER_NAME", "dev.example.com"),
            Map.entry("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("server.pem")),
            Map.entry("LOOKAHEAD_TLS_SERVER_KEY", text("server.key")),
            Map.entry("LOOKAHEAD_TLS_TRUST", text("ca.pem")),
            Map.entry("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("client.pem")),
            Map.entry("LOOKAHEAD_TLS_CLIENT_KEY", text("client.key")),
            Map.entry("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-gateway-secret"),
            Map.entry("APP_OAUTH_CLIENT_ID", "SyntheticClient1"),
            Map.entry("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "synthetic-oauth-secret")));
  }

  /**
   * The two admission values the start required until 2026-11-26 (DLV-1015); nothing reads them
   * now.
   */
  Map<String, String> admission() {
    var values = new LinkedHashMap<String, String>();
    values.put("LOOKAHEAD_ADMISSION_CLIENT_ID", "SyntheticClient2");
    values.put("LOOKAHEAD_ADMISSION_CLIENT_SECRET", "synthetic-admission-secret");
    return values;
  }
}
