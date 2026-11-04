package com.lookahead.gateway.tls;

import com.lookahead.gateway.StartupLog;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Startup validation only: no secret retrieval, files or private exception causes. A rejection logs one
 * {@code startup.refused} line naming the injected variable(s) and a stable reason code (DLV-969); never a value,
 * certificate, key or exception message.
 */
public final class InjectedCredentialValidator {
    static final String REFUSED = "Injected credential validation failed; application startup denied";
    private InjectedCredentialValidator() { }

    /** Why a credential was rejected: which part of a pair ({@code certificate}, {@code key}, {@code name}, {@code trust}) and a code. */
    static final class Invalid extends IllegalArgumentException {
        final String part;
        final String reason;
        Invalid(String part, String reason) { super(reason, null); this.part = part; this.reason = reason; }
        @Override public synchronized Throwable fillInStackTrace() { return this; }
    }

    static Invalid invalid(String reason) { return new Invalid(null, reason); }

    public static Map<String, Object> properties(Map<String, String> input, String service) {
        // The variable(s) being checked, for the refusal line; the pair checks name their part through Invalid.part.
        Map<String, String> parts = Map.of("value", "service");
        try {
            if (!Set.of("gateway", "domain").contains(service)) throw invalid("UNKNOWN_SERVICE");
            parts = Map.of("value", "LOOKAHEAD_TLS_SCHEMA");
            String schema = input.get("LOOKAHEAD_TLS_SCHEMA");
            if (!"lookahead-tls/v1".equals(schema)) throw invalid(schema == null ? "MISSING" : "UNSUPPORTED_SCHEMA");
            String certificate = input.get("LOOKAHEAD_TLS_SERVER_CERTIFICATE");
            String key = input.get("LOOKAHEAD_TLS_SERVER_KEY");
            String trust = input.get("LOOKAHEAD_TLS_TRUST");
            String serverTrust = service.equals("gateway") ? "the JVM default trust store" : "LOOKAHEAD_TLS_TRUST";
            parts = Map.of("certificate", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "key", "LOOKAHEAD_TLS_SERVER_KEY",
                    "name", "LOOKAHEAD_TLS_SERVER_NAME", "trust", serverTrust,
                    "chain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE (its chain to " + serverTrust + ")");
            validatePair(certificate, key, service.equals("gateway") ? null : trust,
                    input.get("LOOKAHEAD_TLS_SERVER_NAME"), false);
            parts = Map.of("value", "LOOKAHEAD_TLS_TRUST");
            trustAnchors(trust);
            Map<String, Object> values = new LinkedHashMap<>();
            values.put("spring.ssl.bundle.pem.serving.keystore.certificate", certificate);
            values.put("spring.ssl.bundle.pem.serving.keystore.private-key", key);
            parts = Map.of("value", "LOOKAHEAD_DOMAIN_GATEWAY_SECRET");
            values.put("app.cognito.gateway-secret", scalar(input.get("LOOKAHEAD_DOMAIN_GATEWAY_SECRET")));
            if (service.equals("gateway")) {
                String client = input.get("LOOKAHEAD_TLS_CLIENT_CERTIFICATE");
                String clientKey = input.get("LOOKAHEAD_TLS_CLIENT_KEY");
                parts = Map.of("certificate", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "key", "LOOKAHEAD_TLS_CLIENT_KEY",
                        "name", "the fixed client name gateway.lookahead-dev.internal", "trust", "LOOKAHEAD_TLS_TRUST",
                        "chain", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE (its chain to LOOKAHEAD_TLS_TRUST)");
                validatePair(client, clientKey, trust, "gateway.lookahead-dev.internal", true);
                parts = Map.of("value", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE");
                if (Arrays.equals(certificates(certificate).getFirst().getPublicKey().getEncoded(),
                        certificates(client).getFirst().getPublicKey().getEncoded())) throw invalid("SAME_KEY_AS_SERVER_CERTIFICATE");
                values.put("spring.ssl.bundle.pem.internal.keystore.certificate", client);
                values.put("spring.ssl.bundle.pem.internal.keystore.private-key", clientKey);
                values.put("spring.ssl.bundle.pem.internal.truststore.certificate", trust);
                parts = Map.of("value", "APP_OAUTH_CLIENT_ID");
                values.put("app.oauth.client-id", clientId(input.get("APP_OAUTH_CLIENT_ID")));
                parts = Map.of("value", "LOOKAHEAD_GATEWAY_CLIENT_SECRET");
                values.put("app.oauth.client-secret", scalar(input.get("LOOKAHEAD_GATEWAY_CLIENT_SECRET")));
                parts = Map.of("value", "LOOKAHEAD_ADMISSION_CLIENT_ID");
                values.put("app.admission.client-id", clientId(input.get("LOOKAHEAD_ADMISSION_CLIENT_ID")));
                parts = Map.of("value", "LOOKAHEAD_ADMISSION_CLIENT_SECRET");
                values.put("app.admission.client-secret", scalar(input.get("LOOKAHEAD_ADMISSION_CLIENT_SECRET")));
            } else {
                parts = Map.of("value", "LOOKAHEAD_DOMAIN_DB_PASSWORD");
                String password = scalar(input.get("LOOKAHEAD_DOMAIN_DB_PASSWORD"));
                if (!password.matches("[A-Za-z0-9]{48}")) throw invalid("NOT_48_ALPHANUMERIC_CHARACTERS");
                values.put("spring.datasource.password", password);
                values.put("spring.ssl.bundle.pem.serving.truststore.certificate", trust);
            }
            return values;
        } catch (Exception rejected) {
            // Parse/binding exceptions may contain PEM or scalar values. Do not retain the cause; log names and codes only.
            String part = rejected instanceof Invalid invalid && invalid.part != null ? invalid.part : "value";
            String setting = parts.getOrDefault(part, parts.getOrDefault("value", String.join(", ", new TreeSet<>(parts.values()))));
            throw StartupLog.refused("injected credential " + setting, reason(rejected), REFUSED);
        }
    }

    /** A stable code for a rejection: ours, or the JDK exception's type (never its message, which can quote the input). */
    static String reason(Exception rejected) {
        if (rejected instanceof Invalid invalid) return invalid.reason;
        if (rejected instanceof CertificateExpiredException) return "CERTIFICATE_EXPIRED";
        if (rejected instanceof CertificateNotYetValidException) return "CERTIFICATE_NOT_YET_VALID";
        if (rejected instanceof CertPathBuilderException) return "CHAIN_NOT_TRUSTED";
        if (rejected instanceof CertificateException) return "CERTIFICATE_UNREADABLE";
        if (rejected instanceof InvalidKeySpecException) return "KEY_UNREADABLE";
        if (rejected instanceof SignatureException || rejected instanceof InvalidKeyException) return "KEY_DOES_NOT_MATCH_CERTIFICATE";
        return rejected.getClass().getSimpleName();
    }

    static String scalar(String value) {
        if (value == null) throw invalid("MISSING");
        if (value.length() < 16 || value.length() > 4096) throw invalid("LENGTH_OUTSIDE_16_TO_4096");
        if (value.codePoints().anyMatch(Character::isISOControl)) throw invalid("CONTROL_CHARACTERS");
        return value;
    }

    static String clientId(String value) {
        if (value == null) throw invalid("MISSING");
        if (!value.matches("[A-Za-z0-9]{1,128}")) throw invalid("NOT_1_TO_128_ALPHANUMERIC_CHARACTERS");
        return value;
    }
    static List<X509Certificate> certificates(String pem) throws Exception {
        if (pem == null) throw invalid("MISSING");
        if (pem.length() > 65536) throw invalid("LONGER_THAN_64_KB");
        var values = CertificateFactory.getInstance("X.509").generateCertificates(new java.io.ByteArrayInputStream(pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        if (values.isEmpty()) throw invalid("NO_CERTIFICATE");
        if (values.size() > 8) throw invalid("MORE_THAN_8_CERTIFICATES");
        List<X509Certificate> result = new ArrayList<>();
        for (var value : values) { var certificate = (X509Certificate) value; certificate.checkValidity(); result.add(certificate); }
        return result;
    }
    static Set<TrustAnchor> trustAnchors(String pem) throws Exception {
        Set<TrustAnchor> anchors = new HashSet<>();
        for (var cert : certificates(pem)) {
            if (cert.getBasicConstraints() < 0 || !cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) throw invalid("NOT_A_SELF_SIGNED_CA");
            cert.verify(cert.getPublicKey()); anchors.add(new TrustAnchor(cert, null));
        }
        return anchors;
    }

    private interface Step<T> { T run() throws Exception; }

    /** Runs one check of a pair and labels any rejection with the part it was about. */
    private static <T> T in(String part, Step<T> step) {
        try {
            return step.run();
        } catch (Invalid invalid) {
            throw invalid.part == null ? new Invalid(part, invalid.reason) : invalid;
        } catch (Exception failure) {
            throw new Invalid(part, reason(failure));
        }
    }

    public static void validatePair(String pem, String keyPem, String trustPem, String expectedName, boolean client) throws Exception {
        var chain = in("certificate", () -> certificates(pem)); var leaf = chain.getFirst();
        if (leaf.getBasicConstraints() >= 0) throw new Invalid("certificate", "LEAF_IS_A_CA_CERTIFICATE");
        if (expectedName == null) throw new Invalid("name", "MISSING");
        if (!expectedName.matches("[a-z0-9][a-z0-9.-]+")) throw new Invalid("name", "NOT_A_LOWER_CASE_HOST_NAME");
        if (leaf.getNotAfter().toInstant().isBefore(Instant.now().plus(Duration.ofDays(1)))) throw new Invalid("certificate", "EXPIRES_WITHIN_ONE_DAY");
        var sans = in("certificate", leaf::getSubjectAlternativeNames);
        if (sans == null || sans.stream().noneMatch(s -> Integer.valueOf(2).equals(s.get(0)) && expectedName.equals(s.get(1))))
            throw new Invalid("certificate", "NAME_NOT_IN_SUBJECT_ALTERNATIVE_NAMES");
        // NGINX deliberately authorizes the exact Gateway subject. Reject extra
        // RDNs here rather than install credentials that its peer will reject.
        if (client && !leaf.getSubjectX500Principal().equals(
                new javax.security.auth.x500.X500Principal("CN=" + expectedName))) throw new Invalid("certificate", "CLIENT_SUBJECT_NOT_EXACTLY_CN");
        var usages = in("certificate", leaf::getExtendedKeyUsage);
        if (usages == null || !usages.contains(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1"))
            throw new Invalid("certificate", client ? "NOT_FOR_CLIENT_AUTHENTICATION" : "NOT_FOR_SERVER_AUTHENTICATION");
        // Match a complete PKCS8 PEM envelope; never accept extra blocks or trailing material.
        if (keyPem == null) throw new Invalid("key", "MISSING");
        var keyBlock = java.util.regex.Pattern.compile(
                "\\A-{5}BEGIN PRIVATE KEY-{5}\\R([A-Za-z0-9+/=\\r\\n]+)-{5}END PRIVATE KEY-{5}[\\r\\n]*\\z").matcher(keyPem);
        if (!keyBlock.matches()) throw new Invalid("key", "NOT_ONE_PKCS8_PEM_BLOCK");
        var privateKey = in("key", () -> KeyFactory.getInstance(leaf.getPublicKey().getAlgorithm())
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getMimeDecoder().decode(keyBlock.group(1)))));
        boolean matches = in("key", () -> {
            var signature = Signature.getInstance(leaf.getPublicKey().getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA");
            byte[] challenge = new byte[32]; new SecureRandom().nextBytes(challenge);
            signature.initSign(privateKey); signature.update(challenge); byte[] signed = signature.sign();
            signature.initVerify(leaf.getPublicKey()); signature.update(challenge); return signature.verify(signed);
        });
        if (!matches) throw new Invalid("key", "KEY_DOES_NOT_MATCH_CERTIFICATE");
        Set<TrustAnchor> anchors;
        if (trustPem != null) anchors = in("trust", () -> trustAnchors(trustPem));
        else {
            var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init((KeyStore) null);
            anchors = new HashSet<>();
            for (var manager : factory.getTrustManagers()) if (manager instanceof X509TrustManager x509)
                for (var cert : x509.getAcceptedIssuers()) anchors.add(new TrustAnchor(cert, null));
        }
        var selector = new X509CertSelector(); selector.setCertificate(leaf);
        var parameters = new PKIXBuilderParameters(anchors, selector); parameters.setRevocationEnabled(false);
        parameters.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain)));
        in("chain", () -> CertPathBuilder.getInstance("PKIX").build(parameters));
    }
}
