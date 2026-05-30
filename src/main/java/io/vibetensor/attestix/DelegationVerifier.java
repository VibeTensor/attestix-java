package io.vibetensor.attestix;

import io.vibetensor.attestix.crypto.Ed25519;
import io.vibetensor.attestix.json.Json;
import io.vibetensor.attestix.util.Base64Url;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Offline verifier for Attestix UCAN delegation chains.
 *
 * <p>Delegations are <b>EdDSA JWTs</b> (compact serialization), NOT JCS-signed.
 * The signed message is {@code base64url(header) + "." + base64url(payload)}
 * (unpadded, per the JWT spec). Only {@code alg=EdDSA} is accepted —
 * {@code alg:none} and any other algorithm are rejected.
 *
 * <p>Chain verification (mirrors {@code verify_delegation}):
 * <ol>
 *   <li>every JWT signature verifies under the server public key;</li>
 *   <li>no token is expired ({@code exp});</li>
 *   <li>the {@code prf[]} ancestry is recursively verified, rejecting cycles
 *       (a repeated {@code jti});</li>
 *   <li>capability attenuation: the child {@code att} is a subset of the parent
 *       {@code att} (privilege escalation is rejected).</li>
 * </ol>
 */
public final class DelegationVerifier {

    private DelegationVerifier() {}

    /**
     * Verify a root-&gt;child delegation chain.
     *
     * @param parentToken  the parent (root) JWT compact token
     * @param childToken   the child JWT compact token (its {@code prf[]} contains the parent)
     * @param serverPublicKey the raw 32-byte Ed25519 server public key that signs all links
     * @param now          reference time for expiry checks
     */
    public static DelegationResult verifyChain(String parentToken, String childToken,
                                               byte[] serverPublicKey, Instant now) {
        boolean parentSig = verifyJwtSignature(parentToken, serverPublicKey);
        boolean childSig = verifyJwtSignature(childToken, serverPublicKey);

        Map<String, Object> parentPayload = decodePayload(parentToken);
        Map<String, Object> childPayload = decodePayload(childToken);

        boolean notExpired = notExpired(parentPayload, now) && notExpired(childPayload, now);

        // Recursively verify the child's prf[] ancestry (signatures + expiry + cycle-free).
        boolean chainValid = verifyProofChain(childPayload, serverPublicKey, now, new HashSet<>());

        Set<String> parentAtt = attSet(parentPayload);
        Set<String> childAtt = attSet(childPayload);
        boolean subset = parentAtt.containsAll(childAtt);

        return new DelegationResult(
                parentSig && chainValid,
                childSig,
                subset,
                notExpired);
    }

    /** Verify a single JWT compact token's EdDSA signature. Rejects non-EdDSA algorithms. */
    public static boolean verifyJwtSignature(String token, byte[] publicKey) {
        if (token == null) {
            return false;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        Map<String, Object> header = decodeJsonSegment(parts[0]);
        Object alg = header.get("alg");
        if (!"EdDSA".equals(alg)) {
            // Reject alg:none and everything that is not EdDSA.
            return false;
        }
        byte[] signingInput = (parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] signature;
        try {
            signature = Base64Url.decode(parts[2]);
        } catch (RuntimeException ex) {
            return false;
        }
        try {
            return Ed25519.verify(publicKey, signingInput, signature);
        } catch (RuntimeException ex) {
            return false;
        }
    }

    private static boolean verifyProofChain(Map<String, Object> payload, byte[] publicKey,
                                            Instant now, Set<String> seenJti) {
        Object jti = payload.get("jti");
        if (jti instanceof String) {
            if (!seenJti.add((String) jti)) {
                return false; // cycle: repeated jti
            }
        }
        Object prf = payload.get("prf");
        if (!(prf instanceof List)) {
            return true;
        }
        for (Object ancestorObj : (List<?>) prf) {
            if (!(ancestorObj instanceof String)) {
                return false;
            }
            String ancestorToken = (String) ancestorObj;
            if (!verifyJwtSignature(ancestorToken, publicKey)) {
                return false;
            }
            Map<String, Object> ancestorPayload = decodePayload(ancestorToken);
            if (!notExpired(ancestorPayload, now)) {
                return false;
            }
            if (!verifyProofChain(ancestorPayload, publicKey, now, seenJti)) {
                return false;
            }
        }
        return true;
    }

    private static boolean notExpired(Map<String, Object> payload, Instant now) {
        Object exp = payload.get("exp");
        if (exp == null) {
            return true;
        }
        long expSeconds = toLong(exp);
        return now.getEpochSecond() < expSeconds;
    }

    private static Set<String> attSet(Map<String, Object> payload) {
        Set<String> result = new LinkedHashSet<>();
        Object att = payload.get("att");
        if (att instanceof List) {
            for (Object cap : (List<?>) att) {
                if (cap instanceof String) {
                    result.add((String) cap);
                } else {
                    result.add(String.valueOf(cap));
                }
            }
        }
        return result;
    }

    static Map<String, Object> decodePayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new IllegalArgumentException("Malformed JWT");
        }
        return decodeJsonSegment(parts[1]);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> decodeJsonSegment(String segment) {
        byte[] bytes = Base64Url.decode(segment);
        Object parsed = Json.parse(new String(bytes, StandardCharsets.UTF_8));
        if (!(parsed instanceof Map)) {
            throw new IllegalArgumentException("JWT segment is not a JSON object");
        }
        return (Map<String, Object>) parsed;
    }

    private static long toLong(Object v) {
        if (v instanceof BigInteger) {
            return ((BigInteger) v).longValueExact();
        }
        if (v instanceof BigDecimal) {
            return ((BigDecimal) v).longValueExact();
        }
        if (v instanceof Number) {
            return ((Number) v).longValue();
        }
        throw new IllegalArgumentException("Not a numeric claim: " + v);
    }
}
