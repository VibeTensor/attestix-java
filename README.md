# Attestix Java Verifier

Offline Java verifier for Attestix Ed25519 credentials and UCAN-style
compact JWT delegation chains. It needs no Python runtime and makes no network
calls. It does not issue credentials or provide a presentation-verification API.
See the [Attestix core](https://github.com/VibeTensor/attestix) for issuance.

## Build the current source

Build with JDK 17; source and bytecode target Java 11 via `--release 11`.
The checkout uses Bouncy Castle `bcprov-jdk18on` 1.86, as declared in
[build.gradle.kts](build.gradle.kts).

```sh
./gradlew test --no-daemon
./gradlew build --no-daemon
```

The configured publication coordinates are `com.vibetensor:attestix:0.4.1`.
These coordinates do not establish Maven Central availability or publication of
main-branch fixes. Build a reviewed checkout or confirm the contents of the
release you select before depending on its verification behavior.

## Verify a credential with a trusted key

```java
import io.vibetensor.attestix.Attestix;
import io.vibetensor.attestix.DidKey;
import io.vibetensor.attestix.VerificationResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

public final class VerifyExample {
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: VerifyExample credential.json");
        }
        // Obtain and authenticate the expected issuer's key out of band.
        byte[] issuerKey = DidKey.decode(
            "did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev");
        String vcJson = Files.readString(Path.of(args[0]));
        VerificationResult result = Attestix.verifyCredential(vcJson, issuerKey, Instant.now());
        System.out.println("valid=" + result.verify());
    }
}
```

This sample key is an example, not a trust anchor for arbitrary credentials.
The caller supplies the trusted 32-byte issuer key. Verification does not
resolve a key from `proof.verificationMethod` or independently check that the
pinned key corresponds to the document's issuer identifier. Make that trust
association in the application.

## Credential behavior and errors

- `VerificationResult` exposes `signatureValid()`, `notExpired()`,
  `notRevoked()`, `structureValid()`, and their combined `verify()` verdict.
- The signed payload excludes only top-level `proof` and `credentialStatus`.
  NFC-normalized key collisions make signature verification fail.
- Null or wrong-length pinned keys, invalid proof encoding, and canonicalization
  errors do not pass signature verification.
- Absent `expirationDate` means no expiry. A present null, non-string, empty, or
  unparseable value fails the expiry check. Valid expiry requires `now < expiry`.
- Embedded revocation status is read locally. Missing status does not establish
  current revocation state; consult a trusted issuer status source separately.
- Malformed JSON can throw `JsonException`; catch it at the input boundary.
  Direct canonicalization can also throw for unsupported input. Do not interpret
  any exception as a successful verification.
- Structure checks concern the proof shape, not complete W3C schema validation.
  This verifier does not perform JSON-LD processing or legal assessment.

## Delegation verification

```java
DelegationResult result = Attestix.verifyDelegationChain(
    parentJwt, childJwt, trustedServerKey, Instant.now());
boolean valid = result.verify();
```

Import `io.vibetensor.attestix.DelegationResult` for this fragment. The caller
supplies the trusted server key used for every signature. Verification checks
EdDSA signatures, parent/child expiry, the child's recursive `prf` signatures
and expiry, repeated-`jti` cycles, and capability subset between the explicit
parent and child. It does not independently enforce capability attenuation at
every recursive ancestor, `nbf`, `iat`, audience policy, or live revocation.
Apply the required application policy before authorizing an operation.

## Public API

| Method | Purpose |
|---|---|
| `Attestix.verifyCredential(json, issuerKey, now)` | Verify a credential under the caller's trusted key. |
| `Attestix.verifyDelegationChain(parent, child, serverKey, now)` | Verify the explicit pair and the child's proof ancestry. |
| `Attestix.canonicalize(json)` | Produce canonical bytes or throw for invalid/unsupported input. |
| `Attestix.decodeDidKey(did)` | Decode an Ed25519 `did:key` to a 32-byte public key. |

## Canonical form and compatibility

See [CANONICAL.md](CANONICAL.md). Attestix uses NFC normalization, compact UTF-8
JSON, normalized-key sorting, and arbitrary-precision integer handling; it is
not strict RFC 8785. General floating-point interoperability is not guaranteed.

The shared vectors are vendored in [testdata/vectors.json](testdata/vectors.json)
and [src/test/resources/vectors.json](src/test/resources/vectors.json).
[ConformanceVectorsTest.java](src/test/java/io/vibetensor/attestix/ConformanceVectorsTest.java)
checks those represented cases; [SecurityBoundariesTest.java](src/test/java/io/vibetensor/attestix/SecurityBoundariesTest.java)
covers the hardened input boundaries. This is not a guarantee for every JSON
value or every deployment policy.

## Release configuration

The build configures sources/Javadoc artifacts, signing, and the Sonatype
Central Portal. Publication is a separate maintainer operation requiring
credentials and a reviewed version tag. Nothing in this README announces a new
registry release or authorizes publishing artifacts.

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).
