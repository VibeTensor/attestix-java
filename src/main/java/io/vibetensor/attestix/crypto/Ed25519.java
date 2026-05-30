package io.vibetensor.attestix.crypto;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/**
 * Ed25519 (RFC 8032) signature verification, backed by BouncyCastle's pure-Java,
 * deterministic implementation (no JCA provider registration required).
 */
public final class Ed25519 {

    /** Length in bytes of a raw Ed25519 public key. */
    public static final int PUBLIC_KEY_LENGTH = 32;
    /** Length in bytes of an Ed25519 signature. */
    public static final int SIGNATURE_LENGTH = 64;

    private Ed25519() {}

    /**
     * Verify an Ed25519 signature.
     *
     * @param rawPublicKey the 32-byte raw public key
     * @param message      the signed message bytes
     * @param signature    the 64-byte signature
     * @return true iff the signature is valid for the message under the key
     */
    public static boolean verify(byte[] rawPublicKey, byte[] message, byte[] signature) {
        if (rawPublicKey == null || rawPublicKey.length != PUBLIC_KEY_LENGTH) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        if (signature == null || signature.length != SIGNATURE_LENGTH) {
            return false;
        }
        Ed25519PublicKeyParameters pub = new Ed25519PublicKeyParameters(rawPublicKey, 0);
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, pub);
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }
}
