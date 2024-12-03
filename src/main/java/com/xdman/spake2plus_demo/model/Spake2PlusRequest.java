package com.xdman.spake2plus_demo.model;

import java.util.List;

public record Spake2PlusRequest(
    String protocolVersion,
    ScryptConfig scryptConfig,
    byte[] salt,
    String vehicleBrand,
    List<String> supportedVersions
) {
    public record ScryptConfig(
        int n,      // CPU/memory cost parameter
        int r,      // Block size parameter
        int p       // Parallelization parameter
    ) {}
}
