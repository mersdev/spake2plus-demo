package com.xdman.spake2plus_demo.model;

public class VerifierOutput {
    private final byte[] publicShare;
    private final byte[] expectedConfirmationCode;

    public VerifierOutput(byte[] publicShare, byte[] expectedConfirmationCode) {
        this.publicShare = publicShare;
        this.expectedConfirmationCode = expectedConfirmationCode;
    }

    public byte[] getPublicShare() {
        return publicShare;
    }

    public byte[] getExpectedConfirmationCode() {
        return expectedConfirmationCode;
    }
}
