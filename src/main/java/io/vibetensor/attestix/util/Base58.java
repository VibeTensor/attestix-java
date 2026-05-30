package io.vibetensor.attestix.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58 (Bitcoin alphabet) encode/decode, as used by {@code did:key} multibase
 * base58btc. Self-contained, no external dependency.
 */
public final class Base58 {

    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final char[] ALPHABET_CHARS = ALPHABET.toCharArray();
    private static final int BASE = 58;
    private static final int[] INDEXES = new int[128];

    static {
        Arrays.fill(INDEXES, -1);
        for (int i = 0; i < ALPHABET_CHARS.length; i++) {
            INDEXES[ALPHABET_CHARS[i]] = i;
        }
    }

    private Base58() {}

    public static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        int zeros = 0;
        while (zeros < input.length && input[zeros] == 0) {
            zeros++;
        }
        byte[] copy = Arrays.copyOf(input, input.length);
        StringBuilder sb = new StringBuilder();
        int start = zeros;
        while (start < copy.length) {
            int remainder = divmod(copy, start, 256, BASE);
            sb.append(ALPHABET_CHARS[remainder]);
            if (copy[start] == 0) {
                start++;
            }
        }
        for (int i = 0; i < zeros; i++) {
            sb.append(ALPHABET_CHARS[0]);
        }
        return sb.reverse().toString();
    }

    public static byte[] decode(String input) {
        if (input.isEmpty()) {
            return new byte[0];
        }
        byte[] input58 = new byte[input.length()];
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            int digit = c < 128 ? INDEXES[c] : -1;
            if (digit < 0) {
                throw new IllegalArgumentException("Invalid base58 character '" + c + "'");
            }
            input58[i] = (byte) digit;
        }
        int zeros = 0;
        while (zeros < input58.length && input58[zeros] == 0) {
            zeros++;
        }
        byte[] decoded = new byte[input.length()];
        int outputStart = decoded.length;
        for (int inputStart = zeros; inputStart < input58.length; ) {
            decoded[--outputStart] = divmod(input58, inputStart, BASE, 256);
            if (input58[inputStart] == 0) {
                inputStart++;
            }
        }
        while (outputStart < decoded.length && decoded[outputStart] == 0) {
            outputStart++;
        }
        byte[] result = new byte[zeros + (decoded.length - outputStart)];
        System.arraycopy(decoded, outputStart, result, zeros, decoded.length - outputStart);
        return result;
    }

    private static byte divmod(byte[] number, int firstDigit, int base, int divisor) {
        int remainder = 0;
        for (int i = firstDigit; i < number.length; i++) {
            int digit = number[i] & 0xFF;
            int temp = remainder * base + digit;
            number[i] = (byte) (temp / divisor);
            remainder = temp % divisor;
        }
        return (byte) remainder;
    }

    /** Convenience used only for cross-checking against BigInteger-based encoders. */
    static BigInteger toBigInteger(byte[] bytes) {
        return new BigInteger(1, bytes);
    }
}
