package com.lookahead.gateway.security.tls;

import static org.junit.jupiter.api.Assertions.*;

import ch.qos.logback.classic.Level;
import com.lookahead.gateway.log.LogCapture;
import java.util.*;
import org.junit.jupiter.api.*;

/**
 * The checks of the injected credentials, driven directly: each refusal, and the line that names
 * the input and why.
 */
class InjectedCredentialValidatorTest extends InjectedCredentialFixture {
  /**
   * A PEM header of the wrong kind (PKCS#1, not PKCS#8) with no key in it. Built from two parts so
   * that no secret scanner reads it as a key.
   */
  private static final String NOT_PKCS8_KEY = "-----BEGIN RSA " + "PRIVATE KEY-----\ninvalid";

  @Test
  void missingInputsRejectBeforeContextRefreshWithoutLeakingValues() throws Exception {
    var keys = new ArrayList<>(input().keySet());
    for (String key : keys) {
      var values = input();
      values.remove(key);
      var failure =
          assertThrows(
              IllegalStateException.class, () -> InjectedCredentialValidator.validate(values), key);
      assertEquals(
          "Injected credential validation failed; application startup denied",
          failure.getMessage());
      assertNull(failure.getCause());
    }
  }

  @Test
  void wrongHostnamePurposeKeyAndTrustReject() throws Exception {
    for (var entry :
        Map.of(
                "LOOKAHEAD_TLS_SERVER_NAME",
                "wrong.example.com",
                "LOOKAHEAD_TLS_SERVER_KEY",
                text("ca.key"),
                "LOOKAHEAD_TLS_TRUST",
                text("server.pem"),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                text("client.pem"),
                "LOOKAHEAD_TLS_SCHEMA",
                "wrong")
            .entrySet()) {
      var values = input();
      values.put(entry.getKey(), entry.getValue());
      assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    }
    command(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "other.key",
        "-out",
        "other.pem",
        "-days",
        "5",
        "-subj",
        "/CN=Untrusted root",
        "-addext",
        "basicConstraints=critical,CA:TRUE");
    var values = input();
    values.put("LOOKAHEAD_TLS_TRUST", text("other.pem"));
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
  }

  @Test
  void shortLifetimeExpiredAndWrongClientSubjectReject() throws Exception {
    for (String days : List.of("1", "expired", "future")) {
      leaf("short", "/CN=dev.example.com", "dev.example.com", "serverAuth", days, "server.key");
      var values = input();
      values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("short.pem"));
      assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    }
    leaf(
        "extra",
        "/O=Unexpected/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "client.key");
    var values = input();
    values.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("extra.pem"));
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
  }

  @Test
  void wrongExtendedUsageAndUnsupportedKeyFormatRejectIndependently() throws Exception {
    leaf("purpose", "/CN=dev.example.com", "dev.example.com", "clientAuth", "3", "server.key");
    var values = input();
    values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("purpose.pem"));
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    var badKey = input();
    badKey.put("LOOKAHEAD_TLS_SERVER_KEY", NOT_PKCS8_KEY);
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(badKey));
  }

  @Test
  void privateKeyEnvelopeMustBeCompleteAndContainOnlyOnePkcs8Key() throws Exception {
    String key = text("server.key");
    for (String invalid :
        List.of(
            key.replaceAll("-{5}END PRIVATE KEY-{5}", ""),
            key.replace("END PRIVATE", "END RSA PRIVATE"),
            key.replace("BEGIN PRIVATE", "BEGIN ENCRYPTED PRIVATE"),
            key.replaceFirst("\\R", ""),
            key + key,
            key + "trailing-source",
            "prefix" + key)) {
      var values = input();
      values.put("LOOKAHEAD_TLS_SERVER_KEY", invalid);
      var failure =
          assertThrows(
              IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
      assertEquals(
          "Injected credential validation failed; application startup denied",
          failure.getMessage());
      assertNull(failure.getCause());
    }
  }

  @Test
  void duplicateGatewayKeysAndCaLeafReject() throws Exception {
    leaf(
        "same",
        "/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "server.key");
    var values = input();
    values.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("same.pem"));
    values.put("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key"));
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("ca.pem"));
    values.put("LOOKAHEAD_TLS_SERVER_KEY", text("ca.key"));
    assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
  }

  @Test
  void scalarAndMalformedPemBoundaries() throws Exception {
    for (String scalar : List.of("short", "a".repeat(4097), "synthetic-secret\nvalue")) {
      var values = input();
      values.put("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", scalar);
      assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    }
    for (String pem :
        List.of("", "file:/tmp/forbidden", "x".repeat(65537), text("server.pem").repeat(9))) {
      var values = input();
      values.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", pem);
      assertThrows(IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
    }
    for (String id : List.of("invalid-id", "a".repeat(129)))
      assertThrows(IllegalArgumentException.class, () -> InjectedCredentialValidator.clientId(id));
  }

  // ----- DLV-969 (owner, 2026-11-04): a rejected credential is named in the log, its value never
  // is -----

  /**
   * Runs the validator and returns the one refusal line's setting and reason; the exception stays
   * unchanged.
   */
  List<String> refusal(Map<String, String> values) {
    try (var log = new LogCapture("lookahead.lifecycle")) {
      var failure =
          assertThrows(
              IllegalStateException.class, () -> InjectedCredentialValidator.validate(values));
      assertEquals(
          "Injected credential validation failed; application startup denied",
          failure.getMessage());
      assertNull(failure.getCause());
      assertEquals(1, log.lines().size());
      assertEquals(Level.WARN, log.last().getLevel());
      var secrets =
          new ArrayList<String>(
              List.of(
                  "BEGIN",
                  "PRIVATE KEY",
                  "synthetic-gateway-secret",
                  "synthetic-oauth-secret",
                  "synthetic-admission-secret",
                  "SyntheticClient1",
                  "SyntheticClient2",
                  "aaaaaaaaaaaaaaaa"));
      for (String value : values.values())
        if (value != null && value.length() > 12) secrets.add(value.strip().substring(0, 12));
      secrets.remove("lookahead-tl"); // the schema's value is a fixed, public name
      // The message ends in "startup denied" on purpose: the deploy's log check fails a start on
      // it.
      log.assertNothing(secrets.toArray(String[]::new));
      var pairs = LogCapture.pairs(log.last());
      return List.of(
          pairs.stream()
              .filter(p -> p.startsWith("setting="))
              .findFirst()
              .orElseThrow()
              .substring(8),
          pairs.stream()
              .filter(p -> p.startsWith("reason="))
              .findFirst()
              .orElseThrow()
              .substring(7));
    }
  }

  @Test
  void everyMissingInputIsNamed() throws Exception {
    var keys = new ArrayList<>(input().keySet());
    assertEquals(10, keys.size());
    for (String key : keys) {
      var values = input();
      values.remove(key);
      assertEquals(List.of("injected credential " + key, "MISSING"), refusal(values), key);
    }
  }

  @Test
  void eachRejectionSaysWhichInputAndWhy() throws Exception {
    record Case(String key, String value, String setting, String reason) {}
    command(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "other.key",
        "-out",
        "other.pem",
        "-days",
        "5",
        "-subj",
        "/CN=Untrusted root",
        "-addext",
        "basicConstraints=critical,CA:TRUE");
    leaf("purpose", "/CN=dev.example.com", "dev.example.com", "clientAuth", "3", "server.key");
    leaf("short", "/CN=dev.example.com", "dev.example.com", "serverAuth", "1", "server.key");
    var cases =
        List.of(
            new Case(
                "LOOKAHEAD_TLS_SCHEMA",
                "lookahead-tls/v0",
                "LOOKAHEAD_TLS_SCHEMA",
                "UNSUPPORTED_SCHEMA"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_NAME",
                "wrong.example.com",
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "NAME_NOT_IN_SUBJECT_ALTERNATIVE_NAMES"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_NAME",
                "Not A Name",
                "LOOKAHEAD_TLS_SERVER_NAME",
                "NOT_A_LOWER_CASE_HOST_NAME"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_KEY",
                text("ca.key"),
                "LOOKAHEAD_TLS_SERVER_KEY",
                "KEY_DOES_NOT_MATCH_CERTIFICATE"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_KEY",
                text("client.key"),
                "LOOKAHEAD_TLS_SERVER_KEY",
                "KEY_UNREADABLE"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_KEY",
                NOT_PKCS8_KEY,
                "LOOKAHEAD_TLS_SERVER_KEY",
                "NOT_ONE_PKCS8_PEM_BLOCK"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                text("ca.pem"),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "LEAF_IS_A_CA_CERTIFICATE"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                text("purpose.pem"),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "NOT_FOR_SERVER_AUTHENTICATION"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                text("short.pem"),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "EXPIRES_WITHIN_ONE_DAY"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "file:/tmp/forbidden",
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "CERTIFICATE_UNREADABLE"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "x".repeat(65537),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "LONGER_THAN_64_KB"),
            new Case(
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                text("server.pem").repeat(9),
                "LOOKAHEAD_TLS_SERVER_CERTIFICATE",
                "MORE_THAN_8_CERTIFICATES"),
            new Case(
                "LOOKAHEAD_TLS_TRUST",
                text("server.pem"),
                "LOOKAHEAD_TLS_TRUST",
                "NOT_A_SELF_SIGNED_CA"),
            new Case(
                "LOOKAHEAD_TLS_TRUST",
                text("other.pem"),
                "LOOKAHEAD_TLS_CLIENT_CERTIFICATE (its chain to LOOKAHEAD_TLS_TRUST)",
                "CHAIN_NOT_TRUSTED"),
            new Case(
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "short",
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "LENGTH_OUTSIDE_16_TO_4096"),
            new Case(
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "synthetic-secret\nvalue",
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "CONTROL_CHARACTERS"),
            new Case(
                "APP_OAUTH_CLIENT_ID",
                "invalid-id",
                "APP_OAUTH_CLIENT_ID",
                "NOT_1_TO_128_ALPHANUMERIC_CHARACTERS"),
            new Case(
                "LOOKAHEAD_GATEWAY_CLIENT_SECRET",
                "short",
                "LOOKAHEAD_GATEWAY_CLIENT_SECRET",
                "LENGTH_OUTSIDE_16_TO_4096"));
    for (var test : cases) {
      var values = input();
      values.put(test.key(), test.value());
      assertEquals(
          List.of("injected credential " + test.setting(), test.reason()),
          refusal(values),
          test.toString().substring(0, 80));
    }
    // The client certificate must not reuse the server's key, and its subject must be exactly the
    // Gateway BFF name.
    leaf(
        "same",
        "/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "server.key");
    var same = input();
    same.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("same.pem"));
    same.put("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key"));
    assertEquals(
        List.of(
            "injected credential LOOKAHEAD_TLS_CLIENT_CERTIFICATE",
            "SAME_KEY_AS_SERVER_CERTIFICATE"),
        refusal(same));
    leaf(
        "extra",
        "/O=Unexpected/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "client.key");
    var extra = input();
    extra.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("extra.pem"));
    assertEquals(
        List.of(
            "injected credential LOOKAHEAD_TLS_CLIENT_CERTIFICATE",
            "CLIENT_SUBJECT_NOT_EXACTLY_CN"),
        refusal(extra));
    for (String days : List.of("expired", "future")) {
      leaf("dated", "/CN=dev.example.com", "dev.example.com", "serverAuth", days, "server.key");
      var dated = input();
      dated.put("LOOKAHEAD_TLS_SERVER_CERTIFICATE", text("dated.pem"));
      assertEquals(
          List.of(
              "injected credential LOOKAHEAD_TLS_SERVER_CERTIFICATE",
              days.equals("expired") ? "CERTIFICATE_EXPIRED" : "CERTIFICATE_NOT_YET_VALID"),
          refusal(dated));
    }
  }

  /**
   * DLV-1015: with two faults the refusal is the earlier check's, in the order the checks ran
   * before the properties were built in a step of their own. Expected values measured on the code
   * before the split (snapshot aE3).
   */
  @Test
  void withTwoFaultsTheEarlierCheckRefuses() throws Exception {
    record Fault(String key, String value) {}
    record Case(Fault first, Fault second, String setting, String reason) {}
    leaf(
        "same",
        "/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "server.key");
    leaf(
        "extra",
        "/O=Unexpected/CN=gateway.lookahead-dev.internal",
        "gateway.lookahead-dev.internal",
        "clientAuth",
        "3",
        "client.key");
    var cases =
        List.of(
            new Case(
                new Fault("LOOKAHEAD_TLS_SCHEMA", "lookahead-tls/v0"),
                new Fault("LOOKAHEAD_TLS_SERVER_CERTIFICATE", null),
                "LOOKAHEAD_TLS_SCHEMA",
                "UNSUPPORTED_SCHEMA"),
            new Case(
                new Fault("LOOKAHEAD_TLS_SERVER_KEY", NOT_PKCS8_KEY),
                new Fault("LOOKAHEAD_TLS_TRUST", text("server.pem")),
                "LOOKAHEAD_TLS_SERVER_KEY",
                "NOT_ONE_PKCS8_PEM_BLOCK"),
            new Case(
                new Fault("LOOKAHEAD_TLS_TRUST", text("server.pem")),
                new Fault("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "short"),
                "LOOKAHEAD_TLS_TRUST",
                "NOT_A_SELF_SIGNED_CA"),
            new Case(
                new Fault("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "short"),
                new Fault("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", null),
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "LENGTH_OUTSIDE_16_TO_4096"),
            new Case(
                new Fault("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", null),
                new Fault("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key")),
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "MISSING"),
            new Case(
                new Fault("LOOKAHEAD_DOMAIN_GATEWAY_SECRET", "synthetic-secret\nvalue"),
                new Fault("LOOKAHEAD_GATEWAY_CLIENT_SECRET", null),
                "LOOKAHEAD_DOMAIN_GATEWAY_SECRET",
                "CONTROL_CHARACTERS"),
            new Case(
                new Fault("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("extra.pem")),
                new Fault("APP_OAUTH_CLIENT_ID", "invalid-id"),
                "LOOKAHEAD_TLS_CLIENT_CERTIFICATE",
                "CLIENT_SUBJECT_NOT_EXACTLY_CN"),
            new Case(
                new Fault("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key")),
                new Fault("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "short"),
                "LOOKAHEAD_TLS_CLIENT_KEY",
                "KEY_UNREADABLE"),
            new Case(
                new Fault("APP_OAUTH_CLIENT_ID", "invalid-id"),
                new Fault("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "short"),
                "APP_OAUTH_CLIENT_ID",
                "NOT_1_TO_128_ALPHANUMERIC_CHARACTERS"),
            new Case(
                new Fault("LOOKAHEAD_TLS_SERVER_NAME", "Not A Name"),
                new Fault("LOOKAHEAD_GATEWAY_CLIENT_SECRET", null),
                "LOOKAHEAD_TLS_SERVER_NAME",
                "NOT_A_LOWER_CASE_HOST_NAME"));
    for (var test : cases) {
      var values = input();
      for (var fault : List.of(test.first(), test.second())) {
        if (fault.value() == null) values.remove(fault.key());
        else values.put(fault.key(), fault.value());
      }
      assertEquals(
          List.of("injected credential " + test.setting(), test.reason()),
          refusal(values),
          test.first().key() + " + " + test.second().key());
    }
    // The client certificate that reuses the server's key is refused before either of the two
    // scalars after it.
    var same = input();
    same.put("LOOKAHEAD_TLS_CLIENT_CERTIFICATE", text("same.pem"));
    same.put("LOOKAHEAD_TLS_CLIENT_KEY", text("server.key"));
    same.put("APP_OAUTH_CLIENT_ID", "invalid-id");
    same.remove("LOOKAHEAD_GATEWAY_CLIENT_SECRET");
    assertEquals(
        List.of(
            "injected credential LOOKAHEAD_TLS_CLIENT_CERTIFICATE",
            "SAME_KEY_AS_SERVER_CERTIFICATE"),
        refusal(same));
  }

  // ----- DLV-1015 (owner, 2026-11-26): the start no longer asks for the two admission values -----

  /**
   * Without LOOKAHEAD_ADMISSION_CLIENT_ID and LOOKAHEAD_ADMISSION_CLIENT_SECRET every check passes
   * and nothing is refused.
   */
  @Test
  void aStartWithoutTheAdmissionValuesIsAccepted() throws Exception {
    var values = input();
    assertFalse(values.keySet().stream().anyMatch(key -> key.contains("ADMISSION")));
    try (var log = new LogCapture("lookahead.lifecycle")) {
      var checked = InjectedCredentialValidator.validate(values);
      assertEquals(
          new InjectedCredentialValidator.Checked(
              text("server.pem"),
              text("server.key"),
              "synthetic-gateway-secret",
              text("client.pem"),
              text("client.key"),
              text("ca.pem"),
              "SyntheticClient1",
              "synthetic-oauth-secret"),
          checked);
      assertEquals(
          List.of(
              "serverCertificate",
              "serverKey",
              "domainSecret",
              "clientCertificate",
              "clientKey",
              "trust",
              "oauthClientId",
              "oauthClientSecret"),
          Arrays.stream(InjectedCredentialValidator.Checked.class.getRecordComponents())
              .map(component -> component.getName())
              .toList());
      assertEquals(0, log.lines().size());
    }
  }

  /**
   * Supplied anyway, well formed or not, the two admission values change nothing: same result, same
   * refusals, no line about them.
   */
  @Test
  void suppliedAdmissionValuesAreIgnored() throws Exception {
    var expected = InjectedCredentialValidator.validate(input());
    var malformed = new ArrayList<Map<String, String>>();
    malformed.add(admission());
    for (String id : Arrays.asList("invalid-id", "a".repeat(129), ""))
      for (String secret : Arrays.asList("short", "a".repeat(4097), "synthetic-secret\nvalue")) {
        var pair = new LinkedHashMap<String, String>();
        pair.put("LOOKAHEAD_ADMISSION_CLIENT_ID", id);
        pair.put("LOOKAHEAD_ADMISSION_CLIENT_SECRET", secret);
        malformed.add(pair);
      }
    for (var admission : malformed) {
      var values = input();
      values.putAll(admission);
      try (var log = new LogCapture("lookahead.lifecycle")) {
        assertEquals(expected, InjectedCredentialValidator.validate(values), admission.toString());
        assertEquals(0, log.lines().size());
      }
      // A real fault is refused exactly as without them: the last check of the order, and the
      // first.
      var late = input();
      late.putAll(admission);
      late.put("LOOKAHEAD_GATEWAY_CLIENT_SECRET", "short");
      assertEquals(
          List.of(
              "injected credential LOOKAHEAD_GATEWAY_CLIENT_SECRET", "LENGTH_OUTSIDE_16_TO_4096"),
          refusal(late));
      var early = input();
      early.putAll(admission);
      early.put("LOOKAHEAD_TLS_SCHEMA", "lookahead-tls/v0");
      assertEquals(
          List.of("injected credential LOOKAHEAD_TLS_SCHEMA", "UNSUPPORTED_SCHEMA"),
          refusal(early));
    }
  }
}
