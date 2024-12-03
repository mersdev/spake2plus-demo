package com.xdman.spake2plus_demo.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.spec.SecretKeySpec;

import com.xdman.spake2plus_demo.model.ProverOutput;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import java.math.BigInteger;

public class Spake2PlusService {
    // Cryptographic Constants
    private static final String CURVE_NAME = "secp256r1";
    private static final int SCRYPT_N = 32768;  // CPU/memory cost parameter
    private static final int SCRYPT_R = 8;      // Block size parameter
    private static final int SCRYPT_P = 1;      // Parallelization parameter
    private static final int DERIVED_KEY_LENGTH = 32;

    // Prover and Verifier Configuration
    private final byte[] w0;
    private final byte[] w1;
    private final byte[] L;
    private final SecureRandom secureRandom;

    public Spake2PlusService() {
        this.secureRandom = new SecureRandom();
        // Generate random w0, w1, L for demonstration
        this.w0 = generateRandomBytes(32);
        this.w1 = generateRandomBytes(32);
        this.L = generateRandomBytes(32);
    }

    // Scrypt-based Key Derivation
    private byte[] deriveScryptKey(String password, byte[] salt) {
        return SCrypt.generate(
                password.getBytes(StandardCharsets.UTF_8),
                salt,
                SCRYPT_N,
                SCRYPT_R,
                SCRYPT_P,
                DERIVED_KEY_LENGTH
        );
    }

    // HKDF-like Key Derivation
    private byte[] hkdfExpand(byte[] ikm, String info) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(ikm, "HmacSHA256"));
            hmac.update(info.getBytes(StandardCharsets.UTF_8));
            return hmac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Key derivation failed", e);
        }
    }

    // Secure Random Byte Generation
    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    // Simulation of Network Communication
    public KeyExchangeResult performKeyExchange(String password, String context) {
        try {
            // Derive initial key material
            byte[] salt = generateRandomBytes(16);
            byte[] initialKey = deriveScryptKey(password, salt);

            // Prover Side
            ProverOutput proverOutput = proverKeyGeneration(initialKey, context);

            // Verifier Side
            VerifierOutput verifierOutput = verifierKeyGeneration(
                    proverOutput.publicShare(),
                    initialKey,
                    context
            );

            // Verify Confirmation Codes
            if (!Arrays.equals(proverOutput.confirmationCode(), verifierOutput.expectedConfirmationCode)) {
                throw new SecurityException("Confirmation code mismatch");
            }

            // Derive Final Shared Secret
            byte[] sharedSecret = hkdfExpand(
                    proverOutput.sharedSecretMaterial(),
                    "FinalSharedSecret"
            );

            return new KeyExchangeResult(
                    sharedSecret,
                    salt,
                    proverOutput.publicShare(),
                    verifierOutput.publicShare
            );

        } catch (Exception e) {
            throw new RuntimeException("Key exchange failed", e);
        }
    }

    private ProverOutput proverKeyGeneration(byte[] initialKey, String context) {
        // Generate Prover's Public Share
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        BigInteger x = new BigInteger(256, secureRandom);
        ECPoint G = spec.getG();
        ECPoint M = G.multiply(new BigInteger(1, w0));

        ECPoint X = G.multiply(x).add(M);
        byte[] publicShare = X.getEncoded(false);

        // Compute Shared Secret Material
        byte[] sharedSecretMaterial = computeSharedSecretMaterial(
                X,
                context.getBytes(StandardCharsets.UTF_8),
                initialKey
        );

        // Generate Confirmation Code
        byte[] confirmationCode = generateConfirmationCode(
                sharedSecretMaterial,
                publicShare
        );

        return new ProverOutput(
                publicShare,
                sharedSecretMaterial,
                confirmationCode
        );
    }

    private VerifierOutput verifierKeyGeneration(
            byte[] proverPublicShare,
            byte[] initialKey,
            String context
    ) {
        // Generate Verifier's Public Share
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        BigInteger y = new BigInteger(256, secureRandom);
        ECPoint G = spec.getG();
        ECPoint N = G.multiply(new BigInteger(1, L));

        ECPoint Y = G.multiply(y).add(N);
        byte[] publicShare = Y.getEncoded(false);

        // Compute Shared Secret Material
        byte[] sharedSecretMaterial = computeSharedSecretMaterial(
                Y,
                context.getBytes(StandardCharsets.UTF_8),
                initialKey
        );

        // Generate Expected Confirmation Code
        byte[] expectedConfirmationCode = generateConfirmationCode(
                sharedSecretMaterial,
                proverPublicShare
        );

        return new VerifierOutput(
                publicShare,
                expectedConfirmationCode
        );
    }

    private byte[] computeSharedSecretMaterial(
            ECPoint point,
            byte[] context,
            byte[] initialKey
    ) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(initialKey, "HmacSHA256"));
            hmac.update(point.getEncoded(false));
            hmac.update(context);
            return hmac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Shared secret computation failed", e);
        }
    }

    private byte[] generateConfirmationCode(
            byte[] sharedSecretMaterial,
            byte[] publicShare
    ) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(sharedSecretMaterial, "HmacSHA256"));
            hmac.update(publicShare);
            return hmac.doFinal();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Confirmation code generation failed", e);
        }
    }

    // Nested Classes for Structured Output


    private static class VerifierOutput {
        final byte[] publicShare;
        final byte[] expectedConfirmationCode;

        VerifierOutput(byte[] publicShare, byte[] expectedConfirmationCode) {
            this.publicShare = publicShare;
            this.expectedConfirmationCode = expectedConfirmationCode;
        }
    }

    // Result of Key Exchange
    public static class KeyExchangeResult {
        public final byte[] sharedSecret;
        public final byte[] salt;
        public final byte[] proverPublicShare;
        public final byte[] verifierPublicShare;

        KeyExchangeResult(
                byte[] sharedSecret,
                byte[] salt,
                byte[] proverPublicShare,
                byte[] verifierPublicShare
        ) {
            this.sharedSecret = sharedSecret;
            this.salt = salt;
            this.proverPublicShare = proverPublicShare;
            this.verifierPublicShare = verifierPublicShare;
        }
    }

    // Example Usage Method
    public static void main(String[] args) {
        Spake2PlusService service = new Spake2PlusService();

        try {
            // Simulate key exchange
            KeyExchangeResult result = service.performKeyExchange(
                    "MySecurePassword123",
                    "ExampleKeyExchangeContext"
            );

            // Print out results (in a real scenario, these would be securely handled)
            System.out.println("Shared Secret: " + Hex.toHexString(result.sharedSecret));
            System.out.println("Salt: " + Hex.toHexString(result.salt));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}