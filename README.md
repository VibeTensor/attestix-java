# Attestix Java Verifier

Offline verifier for **Attestix**-issued credentials, in pure Java. Verify
Ed25519 [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) and
[UCAN](https://github.com/ucan-wg/spec) delegation chains that were issued by the
[Attestix](https://github.com/VibeTensor/attestix) Python core (**with no Python
runtime needed**).

This is a language port of the Attestix verifier. It reproduces the Attestix
canonical form **byte-for-byte** and is validated against the shared
cross-language conformance vectors (`spec/verify/v1/vectors.json` in the parent
repo, vendored here under `testdata/` and `src/test/resources/`).

This port is **verifier-only**: it verifies credentials and delegation chains;
it does not issue them. Issuance stays in the Attestix Python core
(`pip install attestix`) or Attestix Cloud.

- Parent project: <https://github.com/VibeTensor/attestix>
- Bundle wire-format spec: <https://attestix.io/spec/bundle/v1>
- Ed25519 via [BouncyCastle](https://www.bouncycastle.org/) (trusted, deterministic)

> **Canonical form note.** Attestix uses a **JCS-*style*** canonical form, **not
> strict RFC 8785.** The load-bearing divergence: Attestix applies Unicode **NFC
> normalization** to every string value and object key (RFC 8785 does not), and
> whole-number floats collapse to integers (`1.0` → `1`). See
> [`CANONICAL.md`](./CANONICAL.md) for the full rules.

## Install

Maven (once published to Maven Central):

```xml
<dependency>
  <groupId>com.vibetensor</groupId>
  <artifactId>attestix</artifactId>
  <version>0.4.0</version>
</dependency>
```

Gradle (Kotlin DSL):

```kotlin
implementation("com.vibetensor:attestix:0.4.0")
```

Requires Java 11+ at runtime. (CI builds and tests on Temurin 17.)

## Verify a credential (10 lines)

```java
import io.vibetensor.attestix.*;
import java.time.Instant;

// The issuer's did:key (published out of band, e.g. in the agent card).
byte[] issuerKey = DidKey.decode("did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev");

String vcJson = /* the credential JSON, e.g. read from a file */ "...";
VerificationResult r = Attestix.verifyCredential(vcJson, issuerKey, Instant.now());

System.out.println("signature valid: " + r.signatureValid());
System.out.println("not expired:     " + r.notExpired());
System.out.println("not revoked:     " + r.notRevoked());
System.out.println("overall verify:  " + r.verify());   // AND of all checks
```

## Verify a delegation chain

```java
byte[] serverKey = DidKey.decode("did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev");
DelegationResult d = Attestix.verifyDelegationChain(parentJwt, childJwt, serverKey, Instant.now());
// d.verify() == every JWT signature valid AND child att ⊆ parent att AND not expired
```

UCAN delegations are EdDSA JWTs (compact form), **not** JCS-signed. Only
`alg=EdDSA` is accepted (`alg:none` is rejected). Capability attenuation is
enforced: a child's capabilities must be a subset of its parent's.

## Decode a did:key

```java
byte[] rawEd25519 = Attestix.decodeDidKey("did:key:z6Mko5TBPGKHkCxSgmf3aC6p6SGj2auwCfRmBydXJFEwL4ev");
// rawEd25519 is the 32-byte public key (multibase base58btc + 0xed01 multicodec prefix)
```

## Canonicalize JSON (the Attestix way)

```java
byte[] canonical = Attestix.canonicalize("{\"b\":2,\"a\":1}");
// -> bytes of {"a":1,"b":2}  (keys sorted by code point, no whitespace, raw UTF-8, NFC)
```

## Public API

| Method | Purpose |
|---|---|
| `Attestix.verifyCredential(vcJson, issuerKey, now)` | Verify a W3C VC → `VerificationResult` |
| `Attestix.verifyDelegationChain(parent, child, serverKey, now)` | Verify a UCAN chain → `DelegationResult` |
| `Attestix.canonicalize(json)` | JCS-style canonical UTF-8 bytes |
| `Attestix.decodeDidKey(did)` | `did:key:z…` → raw 32-byte Ed25519 key |

`VerificationResult` exposes `signatureValid()`, `notExpired()`, `notRevoked()`,
`structureValid()`, and `verify()`.

## Build & test

```bash
./gradlew test     # runs the conformance vectors
./gradlew build    # jar + sources + javadoc
```

CI ([`.github/workflows/test.yml`](.github/workflows/test.yml)) builds and runs
the vectors on Temurin 17 with SHA-pinned actions.

## Conformance

Every vector in `testdata/vectors.json` is asserted by
`src/test/java/io/vibetensor/attestix/ConformanceVectorsTest.java`:

| Vector | What it checks |
|---|---|
| `canon-001` | JCS-style canonical bytes (NFC, sorted keys, whole-float→int, big int) |
| `didkey-001` | did:key decode (0xed01 multicodec, 32-byte key) + round-trip |
| `vc-valid-001` | Valid VC → verify true |
| `vc-tampered-001` | Tampered claim → signature invalid → verify false |
| `vc-expired-001` | Expired VC → not_expired false → verify false |
| `ucan-chain-valid-001` | Delegation chain, child att ⊆ parent att → verify true |
| `ucan-chain-escalation-002` | Privilege escalation (`admin` not in parent) → verify false |

## Releasing to Maven Central

This build is **publish-ready** (POM metadata, sources + javadoc jars, GPG
signing wired) via the Sonatype **Central Portal** (`central.sonatype.com`). To
cut a release:

1. Configure Central Portal token credentials
   (`mavenCentralUsername`, `mavenCentralPassword`) and an in-memory GPG key
   (`signingInMemoryKey`, `signingInMemoryKeyPassword`) as `ORG_GRADLE_PROJECT_*`
   environment variables or Gradle properties.
2. Bump `version` in `build.gradle.kts`, commit, then push a matching `vX.Y.Z`
   tag. The `publish` GitHub Actions workflow runs the conformance vectors and
   then `./gradlew publishToMavenCentral`.
3. With `automaticRelease = true`, Central validates and releases the artifact
   automatically (no manual staging step). Flip that flag to stage first.

No tokens are committed; release runs only on a version tag with the credentials
supplied as encrypted GitHub Actions secrets.

## License

[Apache-2.0](./LICENSE). See [`NOTICE`](./NOTICE).
