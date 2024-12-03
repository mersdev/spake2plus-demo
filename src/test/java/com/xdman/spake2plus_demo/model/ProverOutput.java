package com.xdman.spake2plus_demo.model;

public record ProverOutput(
    byte[] publicShare,
    byte[] sharedSecretMaterial,
    byte[] confirmationCode
) {
}