package com.xdman.spake2plus_demo.model;

public class ProverOutput {
    private final byte[] publicShare;
    private final byte[] sharedSecretMaterial;
    private final byte[] confirmationCode;

    public ProverOutput(byte[] publicShare, byte[] sharedSecretMaterial, byte[] confirmationCode) {
        this.publicShare = publicShare;
        this.sharedSecretMaterial = sharedSecretMaterial;
        this.confirmationCode = confirmationCode;
    }

    public byte[] getPublicShare() {
        return publicShare;
    }

    public byte[] getSharedSecretMaterial() {
        return sharedSecretMaterial;
    }

    public byte[] getConfirmationCode() {
        return confirmationCode;
    }
}
