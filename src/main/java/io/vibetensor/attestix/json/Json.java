package io.vibetensor.attestix.json;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A small, dependency-free JSON parser tailored to the Attestix canonical form.
 *
 * <p>The standard JSON value model used throughout this library:
 * <ul>
 *   <li>{@code null} for JSON null</li>
 *   <li>{@link Boolean} for true/false</li>
 *   <li>{@link BigInteger} for integral numbers (no precision loss, including &gt; 2^53)</li>
 *   <li>{@link BigDecimal} for numbers with a fractional part or exponent</li>
 *   <li>{@link String} for strings</li>
 *   <li>{@link java.util.List List&lt;Object&gt;} for arrays</li>
 *   <li>{@link java.util.LinkedHashMap LinkedHashMap&lt;String,Object&gt;} for objects (insertion order preserved)</li>
 * </ul>
 *
 * <p>Keeping integers as {@link BigInteger} and only falling back to
 * {@link BigDecimal} for genuinely fractional numbers is what lets the
 * canonicaliser reproduce the Python reference behaviour exactly (e.g.
 * {@code 9007199254740993} stays exact, {@code 1.0} is integral, {@code 1.5} is not).
 */
public final class Json {

    private Json() {}

    public static Object parse(String text) {
        Parser p = new Parser(text);
        p.skipWs();
        Object value = p.parseValue();
        p.skipWs();
        if (!p.atEnd()) {
            throw new JsonException("Trailing content at position " + p.pos);
        }
        return value;
    }

    private static final class Parser {
        private final String s;
        int pos;

        Parser(String s) {
            this.s = s;
        }

        boolean atEnd() {
            return pos >= s.length();
        }

        void skipWs() {
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        Object parseValue() {
            if (atEnd()) {
                throw new JsonException("Unexpected end of input");
            }
            char c = s.charAt(pos);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                case 'f':
                    return parseBoolean();
                case 'n':
                    return parseNull();
                default:
                    if (c == '-' || (c >= '0' && c <= '9')) {
                        return parseNumber();
                    }
                    throw new JsonException("Unexpected character '" + c + "' at position " + pos);
            }
        }

        Map<String, Object> parseObject() {
            expect('{');
            LinkedHashMap<String, Object> map = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                if (peek() != '"') {
                    throw new JsonException("Expected string key at position " + pos);
                }
                String key = parseString();
                skipWs();
                expect(':');
                skipWs();
                Object value = parseValue();
                map.put(key, value);
                skipWs();
                char c = next();
                if (c == ',') {
                    continue;
                }
                if (c == '}') {
                    break;
                }
                throw new JsonException("Expected ',' or '}' at position " + (pos - 1));
            }
            return map;
        }

        List<Object> parseArray() {
            expect('[');
            ArrayList<Object> list = new ArrayList<>();
            skipWs();
            if (peek() == ']') {
                pos++;
                return list;
            }
            while (true) {
                skipWs();
                list.add(parseValue());
                skipWs();
                char c = next();
                if (c == ',') {
                    continue;
                }
                if (c == ']') {
                    break;
                }
                throw new JsonException("Expected ',' or ']' at position " + (pos - 1));
            }
            return list;
        }

        String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (atEnd()) {
                    throw new JsonException("Unterminated string");
                }
                char c = s.charAt(pos++);
                if (c == '"') {
                    break;
                }
                if (c == '\\') {
                    if (atEnd()) {
                        throw new JsonException("Unterminated escape");
                    }
                    char e = s.charAt(pos++);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            sb.append(parseUnicodeEscape());
                            break;
                        default:
                            throw new JsonException("Invalid escape '\\" + e + "'");
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private char parseUnicodeEscape() {
            if (pos + 4 > s.length()) {
                throw new JsonException("Invalid \\u escape");
            }
            String hex = s.substring(pos, pos + 4);
            pos += 4;
            try {
                return (char) Integer.parseInt(hex, 16);
            } catch (NumberFormatException ex) {
                throw new JsonException("Invalid \\u escape '" + hex + "'");
            }
        }

        Object parseNumber() {
            int start = pos;
            boolean isDecimal = false;
            if (peek() == '-') {
                pos++;
            }
            while (!atEnd()) {
                char c = s.charAt(pos);
                if (c >= '0' && c <= '9') {
                    pos++;
                } else if (c == '.' || c == 'e' || c == 'E') {
                    isDecimal = true;
                    pos++;
                } else if (c == '+' || c == '-') {
                    // sign within exponent
                    pos++;
                } else {
                    break;
                }
            }
            String num = s.substring(start, pos);
            if (isDecimal) {
                return new BigDecimal(num);
            }
            return new BigInteger(num);
        }

        Boolean parseBoolean() {
            if (s.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            }
            throw new JsonException("Invalid literal at position " + pos);
        }

        Object parseNull() {
            if (s.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            throw new JsonException("Invalid literal at position " + pos);
        }

        private char peek() {
            if (atEnd()) {
                throw new JsonException("Unexpected end of input");
            }
            return s.charAt(pos);
        }

        private char next() {
            if (atEnd()) {
                throw new JsonException("Unexpected end of input");
            }
            return s.charAt(pos++);
        }

        private void expect(char c) {
            if (atEnd() || s.charAt(pos) != c) {
                throw new JsonException("Expected '" + c + "' at position " + pos);
            }
            pos++;
        }
    }
}
