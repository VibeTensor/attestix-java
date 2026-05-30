package io.vibetensor.attestix;

import io.vibetensor.attestix.util.Base58;

import java.util.Arrays;

/**
 * {@code did:key} encode/decode for Ed25519 keys.
 *
 * <p>Format (from {@code attestix/auth/crypto.py}):
 * <pre>
 *   did:key:z + base58btc( 0xed 0x01 || raw-32-byte-ed25519-pubkey )
 * </pre>
 * where {@code 0xed 0x01} is the unsigned-varint multicodec code for
 * {@code ed25519-pub}. The verification-method fragment is {@code <did>#<multibase>}.
 */
public final class DidKey {

    /** Multicodec prefix for ed25519-pub (varint 0xed 0x01). */
    public static final byte[] ED25519_MULTICODEC_PREFIX = {(byte) 0xED, (byte) 0x01};

    private static final String DID_KEY_PREFIX = "did:key:z";

    private DidKey() {}

    /**
     * Decode a {@code did:key:z...} string to the raw 32-byte Ed25519 public key.
     *
     * @throws IllegalArgumentException if the prefix, multicodec, or length is wrong
     */
    public static byte[] decode(String did) {
        if (did == null || !did.startsWith(DID_KEY_PREFIX)) {
            throw new IllegalArgumentException("Not an Ed25519 did:key: " + did);
        }
        String multibase = did.substring("did:key:".length()); // includes leading 'z'
        return decodeMultibase(multibase);
    }

    /**
     * Decode the multibase portion ({@code z...}) of a did:key to the raw 32-byte key.
     */
    public static byte[] decodeMultibase(String multibase) {
        if (multibase == null || multibase.isEmpty() || multibase.charAt(0) != 'z') {
            throw new IllegalArgumentException("Expected base58btc multibase prefix 'z'");
        }
        byte[] decoded = Base58.decode(multibase.substring(1));
        if (decoded.length != 2 + Ed25519PublicKeyLength()) {
            throw new IllegalArgumentException(
                    "Unexpected multicodec payload length: " + decoded.length);
        }
        if (decoded[0] != ED25519_MULTICODEC_PREFIX[0] || decoded[1] != ED25519_MULTICODEC_PREFIX[1]) {
            throw new IllegalArgumentException("Not an ed25519-pub multicodec (expected 0xed01)");
        }
        return Arrays.copyOfRange(decoded, 2, decoded.length);
    }

    /**
     * Encode a raw 32-byte Ed25519 public key as a {@code did:key:z...} string.
     */
    public static String encode(byte[] rawPublicKey) {
        if (rawPublicKey == null || rawPublicKey.length != Ed25519PublicKeyLength()) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        byte[] payload = new byte[2 + rawPublicKey.length];
        payload[0] = ED25519_MULTICODEC_PREFIX[0];
        payload[1] = ED25519_MULTICODEC_PREFIX[1];
        System.arraycopy(rawPublicKey, 0, payload, 2, rawPublicKey.length);
        return DID_KEY_PREFIX + Base58.encode(payload);
    }

    /** The multibase ({@code z...}) form of a raw key, i.e. the did:key minus {@code did:key:}. */
    public static String multibase(byte[] rawPublicKey) {
        return encode(rawPublicKey).substring("did:key:".length());
    }

    /** The verification-method fragment {@code #<multibase>} for a did:key. */
    public static String fragment(String did) {
        return "#" + did.substring("did:key:".length());
    }

    private static int Ed25519PublicKeyLength() {
        return io.vibetensor.attestix.crypto.Ed25519.PUBLIC_KEY_LENGTH;
    }
}
