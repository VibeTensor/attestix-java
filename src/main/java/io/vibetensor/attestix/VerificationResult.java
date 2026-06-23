package io.vibetensor.attestix;

/**
 * Structured result of verifying a W3C Verifiable Credential.
 *
 * <p>{@link #verify()} is the AND of {@link #signatureValid()},
 * {@link #notExpired()}, and {@link #notRevoked()} - and additionally requires
 * {@link #structureValid()}.
 */
public final class VerificationResult {

    private final boolean signatureValid;
    private final boolean notExpired;
    private final boolean notRevoked;
    private final boolean structureValid;

    public VerificationResult(boolean signatureValid, boolean notExpired,
                              boolean notRevoked, boolean structureValid) {
        this.signatureValid = signatureValid;
        this.notExpired = notExpired;
        this.notRevoked = notRevoked;
        this.structureValid = structureValid;
    }

    public boolean signatureValid() {
        return signatureValid;
    }

    public boolean notExpired() {
        return notExpired;
    }

    public boolean notRevoked() {
        return notRevoked;
    }

    public boolean structureValid() {
        return structureValid;
    }

    /** Overall verdict: signature valid AND not expired AND not revoked AND structurally valid. */
    public boolean verify() {
        return signatureValid && notExpired && notRevoked && structureValid;
    }

    @Override
    public String toString() {
        return "VerificationResult{signatureValid=" + signatureValid
                + ", notExpired=" + notExpired
                + ", notRevoked=" + notRevoked
                + ", structureValid=" + structureValid
                + ", verify=" + verify() + '}';
    }
}
