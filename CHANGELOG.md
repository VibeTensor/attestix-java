# Changelog

## Unreleased

These changes describe main-branch source. They do not announce a Maven Central
release or imply that configured version 0.4.1 has been republished.

### Verification

- Reject distinct keys that collide after NFC normalization.
- Treat canonicalization failures and malformed pinned keys as invalid
  signatures; reject malformed present credential expiry values.
- Update Bouncy Castle bcprov-jdk18on to 1.86.

### Documentation

- Explain caller-pinned issuer trust, input exceptions, offline revocation, and
  the explicit pair versus recursive delegation checks.
- Document JDK 17 builds, Java 11 output, and bounded canonical numeric support.
