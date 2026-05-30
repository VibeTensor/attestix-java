package io.vibetensor.attestix;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Produces the Attestix canonical form of a JSON value.
 *
 * <p>This is <b>JCS-style, NOT strict RFC 8785</b>. It reproduces, byte-for-byte,
 * the output of the Python reference
 * {@code attestix/auth/crypto.py::canonicalize_json} (attestix 0.4.0):
 *
 * <ol>
 *   <li>recursively NFC-normalize every string value and every object key
 *       ({@code unicodedata.normalize("NFC", ...)});</li>
 *   <li>whole-number floats serialize as integers ({@code 1.0 -> 1}); ints stay
 *       ints including values &gt; 2^53;</li>
 *   <li>serialize with {@code json.dumps(sort_keys=True, separators=(",",":"),
 *       ensure_ascii=False)} — keys sorted by Unicode code point, no whitespace,
 *       raw UTF-8 with no {@code \\uXXXX} escapes for non-ASCII;</li>
 *   <li>encode UTF-8.</li>
 * </ol>
 *
 * <p>Divergence from strict RFC 8785 that callers MUST honour: RFC 8785 does
 * <i>not</i> normalize Unicode, but Attestix applies NFC. Non-whole floats are
 * formatted via Python's {@code repr}, not ECMAScript Ryū — so signed payloads
 * should avoid non-trivial floats. The conformance vectors only use integers and
 * {@code 1.5}, on which all ports agree.
 */
public final class Canonicalizer {

    private Canonicalizer() {}

    /** Canonicalize a parsed JSON value to its UTF-8 canonical bytes. */
    public static byte[] canonicalize(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Canonicalize and return the canonical form as a Java String (pre-UTF-8 encoding). */
    public static String canonicalString(Object value) {
        StringBuilder sb = new StringBuilder();
        write(sb, value);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object value) {
        if (value == null) {
            sb.append("null");
        } else if (value instanceof Map) {
            writeObject(sb, (Map<?, ?>) value);
        } else if (value instanceof List) {
            writeArray(sb, (List<?>) value);
        } else if (value instanceof String) {
            writeString(sb, (String) value);
        } else if (value instanceof Boolean) {
            sb.append(((Boolean) value) ? "true" : "false");
        } else if (value instanceof BigInteger) {
            sb.append(value.toString());
        } else if (value instanceof BigDecimal) {
            writeDecimal(sb, (BigDecimal) value);
        } else if (value instanceof Integer || value instanceof Long || value instanceof Short
                || value instanceof Byte) {
            sb.append(value.toString());
        } else if (value instanceof Double || value instanceof Float) {
            writeDecimal(sb, new BigDecimal(value.toString()));
        } else {
            throw new IllegalArgumentException(
                    "Unsupported JSON value type: " + value.getClass().getName());
        }
    }

    private static void writeObject(StringBuilder sb, Map<?, ?> map) {
        // sort_keys=True: sort keys by Unicode code point ascending, recursively.
        // NFC-normalize each key BEFORE comparison so the sort matches Python,
        // which normalizes keys then dumps with sort_keys.
        TreeMap<String, Object> sorted = new TreeMap<>(Canonicalizer::compareByCodePoint);
        for (Map.Entry<?, ?> e : map.entrySet()) {
            String key = nfc(String.valueOf(e.getKey()));
            sorted.put(key, e.getValue());
        }
        sb.append('{');
        boolean first = true;
        for (Map.Entry<String, Object> e : sorted.entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            writeString(sb, e.getKey()); // already NFC-normalized
            sb.append(':');
            write(sb, e.getValue());
        }
        sb.append('}');
    }

    private static void writeArray(StringBuilder sb, List<?> list) {
        sb.append('[');
        boolean first = true;
        for (Object item : list) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            write(sb, item);
        }
        sb.append(']');
    }

    /**
     * Write a string with NFC normalization and Python {@code json.dumps}-compatible
     * escaping: only {@code "}, {@code \\}, and the control chars U+0000–U+001F are
     * escaped (short escapes for b/t/n/f/r, {@code \\uXXXX} otherwise). With
     * {@code ensure_ascii=False}, every other character — including all non-ASCII —
     * is emitted raw (UTF-8 on encode). {@code /} is NOT escaped.
     */
    private static void writeString(StringBuilder sb, String rawValue) {
        String value = nfc(rawValue);
        sb.append('"');
        int len = value.length();
        for (int i = 0; i < len; i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"':
                    sb.append("\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\b':
                    sb.append("\\b");
                    break;
                case '\t':
                    sb.append("\\t");
                    break;
                case '\n':
                    sb.append("\\n");
                    break;
                case '\f':
                    sb.append("\\f");
                    break;
                case '\r':
                    sb.append("\\r");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        // Raw character (BMP or surrogate). Surrogate pairs are
                        // written through verbatim and encode as the correct UTF-8
                        // bytes (e.g. an emoji -> 4 bytes).
                        sb.append(c);
                    }
                    break;
            }
        }
        sb.append('"');
    }

    private static void writeDecimal(StringBuilder sb, BigDecimal value) {
        // Whole-number floats collapse to integers (1.0 -> 1, 2.00 -> 2), matching
        // _normalize_for_signing. Guard against negative-zero is moot for BigDecimal
        // (it has no signed zero).
        if (value.stripTrailingZeros().scale() <= 0) {
            sb.append(value.toBigIntegerExact().toString());
        } else {
            // Non-whole decimal. Emit the plain (non-exponent) form. The vectors only
            // use 1.5, which is unambiguous across ports.
            sb.append(value.stripTrailingZeros().toPlainString());
        }
    }

    private static String nfc(String s) {
        return Normalizer.normalize(s, Normalizer.Form.NFC);
    }

    /** Compare two strings by Unicode code point, matching Python's str ordering. */
    private static int compareByCodePoint(String a, String b) {
        int i = 0;
        int j = 0;
        int la = a.length();
        int lb = b.length();
        while (i < la && j < lb) {
            int ca = a.codePointAt(i);
            int cb = b.codePointAt(j);
            if (ca != cb) {
                return Integer.compare(ca, cb);
            }
            i += Character.charCount(ca);
            j += Character.charCount(cb);
        }
        return Integer.compare(la - i, lb - j);
    }
}
