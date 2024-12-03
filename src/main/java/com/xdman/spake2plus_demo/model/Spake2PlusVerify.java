package com.xdman.spake2plus_demo.model;

public record Spake2PlusVerify(
    byte[] Y,    // Verifier's public share
    byte[] M     // Verifier's evidence
) {}
