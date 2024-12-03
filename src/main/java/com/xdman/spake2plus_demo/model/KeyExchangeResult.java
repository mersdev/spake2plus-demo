package com.xdman.spake2plus_demo.model;

public record KeyExchangeResult(
        byte[] sharedSecret,
        byte[] salt,
        byte[] proverPublicShare,
        byte[] verifierPublicShare
) {
}
