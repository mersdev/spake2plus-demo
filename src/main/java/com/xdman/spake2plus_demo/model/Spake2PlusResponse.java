package com.xdman.spake2plus_demo.model;

public record Spake2PlusResponse(
    byte[] X    // Prover's public share
) {}
