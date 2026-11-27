package com.lookahead.gateway.security.tls;

import com.lookahead.gateway.log.OpsLog;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.*;
import java.util.*;
import java.util.regex.Pattern;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

/**
 * Startup validation only: no secret retrieval, files or private exception causes. A rejection logs one
 * {@code startup.refused} line naming the injected variable(s) and a stable reason code (DLV-969); never a value,
 * certificate, key or exception message. The checked values go to {@link InjectedCredentialInitializer#properties}, which only
 * fills the property map.
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

    /** The injected values after every check, in the order {@link InjectedCredentialInitializer#properties} publishes them. */
    record Checked(String serverCertificate, String serverKey, String domainSecret, String clientCertificate, String clientKey,
            String trust, String oauthClientId, String oauthClientSecret) { }

    /** Runs every check of the Gateway BFF's injected inputs in a fixed order; the first one that fails refuses the start. */
    public static Checked validate(Map<String, String> input) {
        // The variable(s) being checked, for the refusal line; the pair checks name their part through Invalid.part.
        Map<String, String> parts = Map.of("value", "LOOKAHEAD_TLS_SCHEMA");
        try {
            String schema = input.get("LOOKAHEAD_TLS_SCHEMA");
            if (!"lookahead-tls/v1".equals(schema)) throw invalid(schema == null ? "MISSING" : "UNSUPPORTED_SCHEMA");
            String certificate = input.get("LOOKAHEAD_TLS_SERVER_CERTIFICATE");
            String key = input.get("LOOKAHEAD_TLS_SERVER_KEY");
            String trust = input.get("LOOKAHEAD_TLS_TRUST");
            String serverTrust = "the JVM default trust store";
            parts = Map.of("certificate", "LOOKAHEAD_TLS_SERVER_CERTIFICATE", "key", "LOOKAHEAD_TLS_SERVER_KEY",
                    "name", "LOOKAHEAD_TLS_SERVER_NAME", "trust", serverTrust,
                    "chain", "LOOKAHEAD_TLS_SERVER_CERTIFICATE (its chain to " + serverTrust + ")");
            validatePair(certificate, key, null, input.get("LOOKAHEAD_TLS_SERVER_NAME"), false);
            parts = Map.of("value", "LOOKAHEAD_TLS_TRUST");
            trustAnchors(trust);
            parts = Map.of("value", "LOOKAHEAD_DOMAIN_GATEWAY_SECRET");
            String domainSecret = scalar(input.get("LOOKAHEAD_DOMAIN_GATEWAY_SECRET"));
            String client = input.get("LOOKAHEAD_TLS_CLIENT_CERTIFICATE");
            String clientKey = input.get("LOOKAHEAD_TLS_CLIENT_KEY");
            parts = Map.of("certificate", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE", "key", "LOOKAHEAD_TLS_CLIENT_KEY",
                    "name", "the fixed client name gateway.lookahead-dev.internal", "trust", "LOOKAHEAD_TLS_TRUST",
                    "chain", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE (its chain to LOOKAHEAD_TLS_TRUST)");
            validatePair(client, clientKey, trust, "gateway.lookahead-dev.internal", true);
            parts = Map.of("value", "LOOKAHEAD_TLS_CLIENT_CERTIFICATE");
            if (Arrays.equals(certificates(certificate).getFirst().getPublicKey().getEncoded(),
                    certificates(client).getFirst().getPublicKey().getEncoded())) throw invalid("SAME_KEY_AS_SERVER_CERTIFICATE");
            parts = Map.of("value", "APP_OAUTH_CLIENT_ID");
            String oauthClientId = clientId(input.get("APP_OAUTH_CLIENT_ID"));
            parts = Map.of("value", "LOOKAHEAD_GATEWAY_CLIENT_SECRET");
            String oauthClientSecret = scalar(input.get("LOOKAHEAD_GATEWAY_CLIENT_SECRET"));
            return new Checked(certificate, key, domainSecret, client, clientKey, trust, oauthClientId, oauthClientSecret);
        } catch (Exception rejected) {
            // Parse/binding exceptions may contain PEM or scalar values. Do not retain the cause; log names and codes only.
            String part = rejected instanceof Invalid invalid && invalid.part != null ? invalid.part : "value";
            String setting = parts.getOrDefault(part, parts.getOrDefault("value", String.join(", ", new TreeSet<>(parts.values()))));
            throw OpsLog.startupRefused("injected credential " + setting, reason(rejected), REFUSED);
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
        var values = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(pem.getBytes(StandardCharsets.US_ASCII)));
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
        // NGINX deliberately authorizes the exact Gateway BFF subject. Reject extra
        // RDNs here rather than install credentials that its peer will reject.
        if (client && !leaf.getSubjectX500Principal().equals(
                new X500Principal("CN=" + expectedName))) throw new Invalid("certificate", "CLIENT_SUBJECT_NOT_EXACTLY_CN");
        var usages = in("certificate", leaf::getExtendedKeyUsage);
        if (usages == null || !usages.contains(client ? "1.3.6.1.5.5.7.3.2" : "1.3.6.1.5.5.7.3.1"))
            throw new Invalid("certificate", client ? "NOT_FOR_CLIENT_AUTHENTICATION" : "NOT_FOR_SERVER_AUTHENTICATION");
        // Match a complete PKCS8 PEM envelope; never accept extra blocks or trailing material.
        if (keyPem == null) throw new Invalid("key", "MISSING");
        var keyBlock = Pattern.compile(
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
