# Attestix canonical form in Java

The implementation follows the Attestix v1 JCS-style signing form for the
represented conformance cases. It is not strict RFC 8785. The shared
[test vectors](testdata/vectors.json) are the compatibility reference.

## Implemented rules

1. NFC-normalize each string value and object key.
2. Reject distinct object keys that become identical after NFC normalization.
3. Sort the normalized keys recursively by Unicode code point.
4. Use compact separators, with no formatting whitespace.
5. Emit non-ASCII strings as UTF-8; escape quotes, backslashes, and control
   characters using JSON escapes.
6. Parse integer tokens into `BigInteger`, preserving values such as
   `9007199254740993` without JavaScript's number rounding.
7. Normalize `BigDecimal` values with `stripTrailingZeros`; whole values emit
   integers and remaining decimal values use the implementation's decimal form.

The public `Attestix.canonicalize(String)` first parses JSON. Malformed JSON
throws `JsonException`. Unsupported values or normalized-key collisions can
throw during canonicalization. Credential verification catches canonicalization
errors in its signature check and returns `signatureValid=false`.

## Numeric and parsing limits

The vectors exercise integers and `1.5`. The implementation uses `BigDecimal`,
not Python's binary floating-point serializer. Exact equivalence for arbitrary
fractions, exponents, and signed-zero values is not established by those vectors.
Prefer integer or string fields for signed data. Callers passing an already
parsed Map must also preserve numeric precision; conversion to binary floating
point can lose information before canonicalization starts.

Collision rejection applies to distinct keys retained in the parsed object.
It is not a guarantee that identical duplicate names in raw JSON are detected
before the parser constructs its Map.

## Signed fields and encodings

- A VC signature covers the credential minus `proof` and `credentialStatus`.
  The verifier uses the caller's trusted issuer key, not unsigned proof metadata.
- A UCAN signature covers the literal compact JWS signing input
  `base64url(header) + "." + base64url(payload)`. It is not canonicalized JSON;
  only `alg=EdDSA` is accepted.
- Ed25519 public keys contain 32 bytes and signatures contain 64 bytes.
- Attestix VC proofs use padded base64url. Delegation compact-JWT segments use
  unpadded base64url.
- An Ed25519 `did:key` is `did:key:z` followed by base58btc of the multicodec
  bytes `0xed 0x01` and the raw public key.
