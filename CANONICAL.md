# Attestix canonical form (Java port notes)

The Attestix canonical form is **JCS-*style*, NOT strict RFC 8785.** This port
reproduces, byte-for-byte, the output of the Python reference
`attestix/auth/crypto.py::canonicalize_json` (attestix 0.4.0). The vectors'
`canonical_bytes_hex` is the oracle.

## The rule

```
canonical_bytes = NFC_normalize_recursive(obj)
               |> json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)
               |> encode("utf-8")
```

with whole-number floats collapsed to integers.

## Exact behaviours this port implements

1. **NFC normalization**: every string **value** and every object **key** is
   `Normalizer.normalize(s, Form.NFC)` before serialization. (`"cafe"+U+0301` →
   `café`.) This is the main divergence from RFC 8785, which does *not* normalize.
2. **Key sorting**: object keys sorted by Unicode **code point** ascending,
   recursively. NFC is applied to keys *before* sorting.
3. **Separators**: `,` between items, `:` between key and value. No whitespace.
4. **Raw UTF-8, no `\uXXXX`**: non-ASCII characters are emitted as raw UTF-8
   bytes (`ensure_ascii=False`). `é` = `c3 a9`, `☃` = `e2 98 83`, `😀` =
   `f0 9f 98 80`.
5. **Whole-number floats → integers**: `1.0` → `1`, `2.00` → `2`. A non-whole
   float keeps its value: `1.5` → `1.5`. (Implemented via `BigDecimal`:
   `stripTrailingZeros().scale() <= 0` means whole.)
6. **Integers stay integers, arbitrary precision**: `9007199254740993` is
   serialized exactly. This port parses integral JSON numbers into
   `java.math.BigInteger`, so there is no `2^53` precision loss.
7. **Control-char escaping**: only `"`, `\`, and U+0000 to U+001F are escaped,
   using `\b \t \n \f \r` where applicable and `\uXXXX` otherwise. `/` is **not**
   escaped. This matches Python's `json.dumps`.

## Float caveat

For non-trivial floating-point values, Python `json.dumps` and ECMAScript Ryū can
disagree. The conformance vectors only use integers and `1.5`, on which all ports
agree. **Signed payloads should avoid non-trivial floats** (e.g. `0.1 + 0.2`).

## Signing & encoding

- **VC**: signed payload is the credential minus `proof` and `credentialStatus`,
  canonicalized as above, Ed25519-signed; `proof.proofValue` is base64url **with
  padding**.
- **UCAN**: EdDSA JWTs (compact form). The signed message is
  `base64url(header) + "." + base64url(payload)` (base64url **without** padding,
  per the JWT spec). Only `alg=EdDSA` is accepted.
- **did:key**: `did:key:z` + base58btc(`0xed 0x01` || raw-32-byte key).
