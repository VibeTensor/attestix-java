package io.vibetensor.attestix.util;

import java.util.Base64;

/**
 * base64url helpers.
 *
 * <p>Two flavours are used by Attestix:
 * <ul>
 *   <li><b>padded</b> base64url for VC {@code proof.proofValue}
 *       ({@code base64.urlsafe_b64encode} in Python always pads);</li>
 *   <li><b>unpadded</b> base64url for JWT compact segments (per the JWT spec).</li>
 * </ul>
 * The decoder accepts both (padding optional).
 */
public final class Base64Url {

    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final Base64.Encoder ENCODER_PADDED = Base64.getUrlEncoder();
    private static final Base64.Encoder ENCODER_UNPADDED = Base64.getUrlEncoder().withoutPadding();

    private Base64Url() {}

    /** Decode base64url, tolerating both padded and unpadded input. */
    public static byte[] decode(String input) {
        return DECODER.decode(input);
    }

    /** Encode base64url WITH padding (VC proofValue style). */
    public static String encodePadded(byte[] data) {
        return ENCODER_PADDED.encodeToString(data);
    }

    /** Encode base64url WITHOUT padding (JWT segment style). */
    public static String encodeUnpadded(byte[] data) {
        return ENCODER_UNPADDED.encodeToString(data);
    }
}
