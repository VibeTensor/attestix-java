package io.vibetensor.attestix;

import io.vibetensor.attestix.crypto.Ed25519;
import io.vibetensor.attestix.json.Json;
import io.vibetensor.attestix.util.Base64Url;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Offline verifier for Attestix-issued W3C Verifiable Credentials (Ed25519).
 *
 * <p>The signed payload is the VC with the mutable fields {@code proof} and
 * {@code credentialStatus} removed, then JCS-canonicalized
 * ({@link Canonicalizer}). The Ed25519 signature lives in
 * {@code proof.proofValue} (padded base64url). Verification ANDs three checks:
 * signature valid, not expired ({@code now < expirationDate}), not revoked
 * ({@code credentialStatus.revoked} falsy).
 */
public final class CredentialVerifier {

    /** Top-level VC fields excluded from the signed payload. */
    public static final Set<String> MUTABLE_FIELDS = Set.of("proof", "credentialStatus");

    private CredentialVerifier() {}

    /** Parse a JSON VC string and verify against the given issuer public key, using {@code now}. */
    public static VerificationResult verifyCredential(String vcJson, byte[] issuerPublicKey, Instant now) {
        Object parsed = Json.parse(vcJson);
        if (!(parsed instanceof Map)) {
            return new VerificationResult(false, false, false, false);
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> vc = (Map<String, Object>) parsed;
        return verifyCredential(vc, issuerPublicKey, now);
    }

    /**
     * Verify a parsed VC.
     *
     * @param vc              the credential as the standard JSON value model (a Map)
     * @param issuerPublicKey the raw 32-byte Ed25519 issuer public key
     * @param now             the reference time for the expiry check
     */
    public static VerificationResult verifyCredential(Map<String, Object> vc, byte[] issuerPublicKey, Instant now) {
        boolean structureValid = true;

        Object proofObj = vc.get("proof");
        String proofValue = null;
        if (proofObj instanceof Map) {
            Object pv = ((Map<?, ?>) proofObj).get("proofValue");
            if (pv instanceof String) {
                proofValue = (String) pv;
            }
        }
        if (proofValue == null) {
            structureValid = false;
        }

        // Build the signed payload: every top-level field EXCEPT the mutable ones.
        Map<String, Object> signedPayload = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : vc.entrySet()) {
            if (!MUTABLE_FIELDS.contains(e.getKey())) {
                signedPayload.put(e.getKey(), e.getValue());
            }
        }

        boolean signatureValid = false;
        if (proofValue != null) {
            byte[] canonical = Canonicalizer.canonicalize(signedPayload);
            try {
                byte[] sig = Base64Url.decode(proofValue);
                signatureValid = Ed25519.verify(issuerPublicKey, canonical, sig);
            } catch (RuntimeException ex) {
                signatureValid = false;
            }
        }

        boolean notExpired = checkNotExpired(vc.get("expirationDate"), now);
        boolean notRevoked = checkNotRevoked(vc.get("credentialStatus"));

        return new VerificationResult(signatureValid, notExpired, notRevoked, structureValid);
    }

    private static boolean checkNotExpired(Object expirationDate, Instant now) {
        if (!(expirationDate instanceof String) || ((String) expirationDate).isEmpty()) {
            // No expiry => never expires.
            return true;
        }
        try {
            Instant exp = OffsetDateTime.parse((String) expirationDate).toInstant();
            return now.isBefore(exp); // now < expirationDate
        } catch (RuntimeException ex) {
            // Unparseable expiry is treated as a structural problem, not "not expired".
            return false;
        }
    }

    private static boolean checkNotRevoked(Object credentialStatus) {
        if (!(credentialStatus instanceof Map)) {
            // No status block available locally => assume not revoked.
            return true;
        }
        Object revoked = ((Map<?, ?>) credentialStatus).get("revoked");
        return !isTruthy(revoked);
    }

    private static boolean isTruthy(Object v) {
        if (v == null) {
            return false;
        }
        if (v instanceof Boolean) {
            return (Boolean) v;
        }
        if (v instanceof String) {
            return !((String) v).isEmpty();
        }
        return true;
    }
}
