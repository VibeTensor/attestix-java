package io.vibetensor.attestix;

import io.vibetensor.attestix.json.Json;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Runs the shared Attestix conformance vectors (spec/verify/v1/vectors.json,
 * vendored into test resources) against this Java port. Every vector is a
 * separate dynamic test; the byte-for-byte canonical match is the oracle.
 */
class ConformanceVectorsTest {

    /** Default reference time used when a vector does not pin one. */
    private static final Instant DEFAULT_NOW = OffsetDateTime.parse("2026-05-30T00:00:00+00:00").toInstant();

    @SuppressWarnings("unchecked")
    private static Map<String, Object> loadVectors() throws Exception {
        try (InputStream in = ConformanceVectorsTest.class.getResourceAsStream("/vectors.json")) {
            assertNotNull(in, "vectors.json must be on the test classpath");
            byte[] bytes = in.readAllBytes();
            return (Map<String, Object>) Json.parse(new String(bytes, StandardCharsets.UTF_8));
        }
    }

    @TestFactory
    List<DynamicTest> conformanceVectors() throws Exception {
        Map<String, Object> root = loadVectors();
        byte[] issuerKey = hexToBytes((String) root.get("issuer_pubkey_raw_hex"));
        List<?> vectors = (List<?>) root.get("vectors");

        List<DynamicTest> tests = new ArrayList<>();
        for (Object vObj : vectors) {
            @SuppressWarnings("unchecked")
            Map<String, Object> vec = (Map<String, Object>) vObj;
            String id = (String) vec.get("id");
            String kind = (String) vec.get("kind");
            tests.add(DynamicTest.dynamicTest(id + " [" + kind + "]", () -> runVector(vec, issuerKey)));
        }
        return tests;
    }

    private void runVector(Map<String, Object> vec, byte[] issuerKey) {
        String kind = (String) vec.get("kind");
        switch (kind) {
            case "canonicalize":
                runCanonicalize(vec);
                break;
            case "did_key_decode":
                runDidKeyDecode(vec);
                break;
            case "verify_credential":
                runVerifyCredential(vec, issuerKey);
                break;
            case "verify_delegation_chain":
                runVerifyDelegation(vec, issuerKey);
                break;
            default:
                fail("Unknown vector kind: " + kind);
        }
    }

    private void runCanonicalize(Map<String, Object> vec) {
        Object input = vec.get("input");
        byte[] canonical = Canonicalizer.canonicalize(input);
        String gotHex = bytesToHex(canonical);
        String wantHex = (String) vec.get("canonical_bytes_hex");
        assertEquals(wantHex, gotHex, "canonical_bytes_hex mismatch");

        @SuppressWarnings("unchecked")
        Map<String, Object> expected = (Map<String, Object>) vec.get("expected");
        String wantUtf8 = (String) expected.get("canonical_utf8");
        assertEquals(wantUtf8, new String(canonical, StandardCharsets.UTF_8), "canonical_utf8 mismatch");
    }

    private void runDidKeyDecode(Map<String, Object> vec) {
        @SuppressWarnings("unchecked")
        Map<String, Object> input = (Map<String, Object>) vec.get("input");
        String did = (String) input.get("did");
        byte[] raw = DidKey.decode(did);

        @SuppressWarnings("unchecked")
        Map<String, Object> expected = (Map<String, Object>) vec.get("expected");
        assertEquals(expected.get("pubkey_raw_hex"), bytesToHex(raw), "pubkey_raw_hex mismatch");
        assertEquals(expected.get("fragment"), DidKey.fragment(did), "fragment mismatch");
        assertEquals(expected.get("multibase_prefix"), "z", "multibase_prefix mismatch");

        // Round-trip: raw -> did:key must reproduce the original.
        assertEquals(did, DidKey.encode(raw), "did:key round-trip mismatch");
    }

    private void runVerifyCredential(Map<String, Object> vec, byte[] issuerKey) {
        @SuppressWarnings("unchecked")
        Map<String, Object> vc = (Map<String, Object>) vec.get("input");
        Instant now = referenceNow(vec);

        VerificationResult result = CredentialVerifier.verifyCredential(vc, issuerKey, now);

        @SuppressWarnings("unchecked")
        Map<String, Object> expected = (Map<String, Object>) vec.get("expected");
        assertEquals(expected.get("signature_valid"), result.signatureValid(), "signature_valid mismatch");
        assertEquals(expected.get("not_expired"), result.notExpired(), "not_expired mismatch");
        assertEquals(expected.get("not_revoked"), result.notRevoked(), "not_revoked mismatch");
        assertEquals(expected.get("verify"), result.verify(), "verify mismatch");

        // Cross-check: the canonical bytes of the signed payload (proof +
        // credentialStatus removed) must match the vector's canonical_bytes_hex.
        if (vec.containsKey("canonical_bytes_hex")) {
            Map<String, Object> signed = new java.util.LinkedHashMap<>();
            for (Map.Entry<String, Object> e : vc.entrySet()) {
                if (!CredentialVerifier.MUTABLE_FIELDS.contains(e.getKey())) {
                    signed.put(e.getKey(), e.getValue());
                }
            }
            assertEquals(vec.get("canonical_bytes_hex"),
                    bytesToHex(Canonicalizer.canonicalize(signed)),
                    "VC signed-payload canonical_bytes_hex mismatch");
        }
    }

    private void runVerifyDelegation(Map<String, Object> vec, byte[] serverKey) {
        @SuppressWarnings("unchecked")
        Map<String, Object> input = (Map<String, Object>) vec.get("input");
        String parentToken = (String) input.get("parent_token");
        String childToken = (String) input.get("token");
        Instant now = referenceNow(vec);

        DelegationResult result = DelegationVerifier.verifyChain(parentToken, childToken, serverKey, now);

        @SuppressWarnings("unchecked")
        Map<String, Object> expected = (Map<String, Object>) vec.get("expected");
        assertEquals(expected.get("parent_signature_valid"), result.parentSignatureValid(),
                "parent_signature_valid mismatch");
        assertEquals(expected.get("child_signature_valid"), result.childSignatureValid(),
                "child_signature_valid mismatch");
        assertEquals(expected.get("attenuation_is_subset"), result.attenuationIsSubset(),
                "attenuation_is_subset mismatch");
        assertEquals(expected.get("verify"), result.verify(), "verify mismatch");
    }

    private Instant referenceNow(Map<String, Object> vec) {
        Object ref = vec.get("now_reference");
        if (ref instanceof String) {
            return OffsetDateTime.parse((String) ref).toInstant();
        }
        return DEFAULT_NOW;
    }

    // ---- hex helpers ----

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return out;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
