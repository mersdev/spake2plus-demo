package com.xdman.spake2plus_demo.model;

public record Spake2PlusVerifyResponse(
    byte[] M    // Prover's evidence
) {}
