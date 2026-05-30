package io.vibetensor.attestix;

import io.vibetensor.attestix.json.Json;

import java.time.Instant;
import java.util.Map;

/**
 * Convenience facade for the Attestix offline verifier.
 *
 * <p>Example:
 * <pre>{@code
 * byte[] issuerKey = DidKey.decode("did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev");
 * VerificationResult r = Attestix.verifyCredential(vcJson, issuerKey, Instant.now());
 * if (r.verify()) {
 *     System.out.println("credential is valid");
 * }
 * }</pre>
 */
public final class Attestix {

    private Attestix() {}

    /** Canonicalize a JSON string to the Attestix JCS-style canonical UTF-8 bytes. */
    public static byte[] canonicalize(String json) {
        return Canonicalizer.canonicalize(Json.parse(json));
    }

    /** Canonicalize a parsed JSON value (standard value model) to canonical UTF-8 bytes. */
    public static byte[] canonicalize(Object value) {
        return Canonicalizer.canonicalize(value);
    }

    /** Decode a {@code did:key:z...} to the raw 32-byte Ed25519 public key. */
    public static byte[] decodeDidKey(String did) {
        return DidKey.decode(did);
    }

    /** Verify a W3C VC (JSON string) against an issuer key at the given time. */
    public static VerificationResult verifyCredential(String vcJson, byte[] issuerPublicKey, Instant now) {
        return CredentialVerifier.verifyCredential(vcJson, issuerPublicKey, now);
    }

    /** Verify a parsed W3C VC against an issuer key at the given time. */
    public static VerificationResult verifyCredential(Map<String, Object> vc, byte[] issuerPublicKey, Instant now) {
        return CredentialVerifier.verifyCredential(vc, issuerPublicKey, now);
    }

    /** Verify a root-&gt;child UCAN delegation chain. */
    public static DelegationResult verifyDelegationChain(String parentToken, String childToken,
                                                         byte[] serverPublicKey, Instant now) {
        return DelegationVerifier.verifyChain(parentToken, childToken, serverPublicKey, now);
    }
}
