package io.vibetensor.attestix;

/** Structured result of verifying a UCAN delegation chain. */
public final class DelegationResult {

    private final boolean parentSignatureValid;
    private final boolean childSignatureValid;
    private final boolean attenuationIsSubset;
    private final boolean notExpired;

    public DelegationResult(boolean parentSignatureValid, boolean childSignatureValid,
                            boolean attenuationIsSubset, boolean notExpired) {
        this.parentSignatureValid = parentSignatureValid;
        this.childSignatureValid = childSignatureValid;
        this.attenuationIsSubset = attenuationIsSubset;
        this.notExpired = notExpired;
    }

    public boolean parentSignatureValid() {
        return parentSignatureValid;
    }

    public boolean childSignatureValid() {
        return childSignatureValid;
    }

    public boolean attenuationIsSubset() {
        return attenuationIsSubset;
    }

    public boolean notExpired() {
        return notExpired;
    }

    /** Overall verdict: every signature valid AND attenuation is a subset AND not expired. */
    public boolean verify() {
        return parentSignatureValid && childSignatureValid && attenuationIsSubset && notExpired;
    }

    @Override
    public String toString() {
        return "DelegationResult{parentSignatureValid=" + parentSignatureValid
                + ", childSignatureValid=" + childSignatureValid
                + ", attenuationIsSubset=" + attenuationIsSubset
                + ", notExpired=" + notExpired
                + ", verify=" + verify() + '}';
    }
}
