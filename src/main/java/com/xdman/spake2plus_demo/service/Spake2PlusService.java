package com.xdman.spake2plus_demo.service;

import com.xdman.spake2plus_demo.model.*;
import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;

@Service
public class Spake2PlusService {
    // Cryptographic Constants
    private static final String CURVE_NAME = "secp256r1";
    private static final String PROTOCOL_VERSION = "1.0";
    private static final List<String> SUPPORTED_VERSIONS = List.of("1.0");
    private static final int DEFAULT_SCRYPT_N = 32768;
    private static final int DEFAULT_SCRYPT_R = 8;
    private static final int DEFAULT_SCRYPT_P = 1;
    private static final int DERIVED_KEY_LENGTH = 32;
    private static final BigInteger p;
    private static final BigInteger h;
    private static final ECPoint G;
    private static final byte[] M_BYTES;
    private static final ECPoint M;
    private static final byte[] N_BYTES;
    private static final ECPoint N;

    static {
        try {
            // Initialize curve parameters
            ECNamedCurveParameterSpec curveParams = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
            ECCurve curve = curveParams.getCurve();
            
            // Initialize prime field characteristic
            p = curve.getField().getCharacteristic();
            h = BigInteger.ONE;
            G = curveParams.getG();

            // Initialize M point using curve's generator point
            BigInteger mScalar = new BigInteger("886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12", 16);
            M = G.multiply(mScalar);

            // Initialize N point using curve's generator point
            BigInteger nScalar = new BigInteger("8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49", 16);
            N = G.multiply(nScalar);

            // Store encoded points for later use
            M_BYTES = M.getEncoded(true);
            N_BYTES = N.getEncoded(true);

            // Validate points are on curve
            if (!validatePoint(M) || !validatePoint(N)) {
                throw new IllegalStateException("Generated points are not on the curve");
            }
        } catch (Exception e) {
            throw new ExceptionInInitializerError("Failed to initialize SPAKE2+ cryptographic parameters: " + e.getMessage());
        }
    }

    private final SecureRandom secureRandom;
    private byte[] w0;  // Password-derived value
    private byte[] w1;  // Prover's secret
    private byte[] L;   // Verifier's secret
    private BigInteger x;  // Prover's ephemeral key
    private BigInteger y;  // Verifier's ephemeral key
    private byte[] sharedK;  // Shared secret K
    private byte[] sharedCK; // Confirmation key
    private byte[] sharedSK; // Session key

    public Spake2PlusService() {
        this.secureRandom = new SecureRandom();
    }

    // Step 1: Verifier initiates SPAKE2+ Request
    public Spake2PlusRequest initiateKeyExchange(String vehicleBrand) {
        byte[] salt = generateRandomBytes(16);
        return new Spake2PlusRequest(
            PROTOCOL_VERSION,
            new Spake2PlusRequest.ScryptConfig(DEFAULT_SCRYPT_N, DEFAULT_SCRYPT_R, DEFAULT_SCRYPT_P),
            salt,
            vehicleBrand,
            SUPPORTED_VERSIONS
        );
    }

    // Step 2: Prover processes request and generates response
    public Spake2PlusResponse processRequest(Spake2PlusRequest request, String password) 
            throws GeneralSecurityException {
        // Derive w0 using Scrypt
        this.w0 = deriveScryptKey(password, request.salt(), 
            request.scryptConfig().n(), 
            request.scryptConfig().r(), 
            request.scryptConfig().p());
        
        // Generate random scalar x and compute X
        this.x = generateSecureScalar(p);
        ECPoint X = G.multiply(x).add(M.multiply(new BigInteger(1, w0)));
        
        byte[] publicShare = X.getEncoded(true);
        byte[] sharedSecretMaterial = computeHMAC(w0, publicShare);
        byte[] confirmationCode = computeHMAC(w1, publicShare);
        
        // Store ProverOutput for later use in verification
        ProverOutput proverOutput = new ProverOutput(publicShare, sharedSecretMaterial, confirmationCode);
        
        // Return only the public share X in the response
        return new Spake2PlusResponse(publicShare);
    }

    // Step 3: Verifier verifies response and generates verify command
    public Spake2PlusVerify verifyAndGenerateEvidence(byte[] proverX) 
            throws GeneralSecurityException {
        // Validate received point X
        ECPoint X = G.getCurve().decodePoint(proverX);
        if (!validatePoint(X)) {
            throw new GeneralSecurityException("Invalid point X received from Prover");
        }

        // Generate random scalar y and compute Y
        this.y = generateSecureScalar(p);
        ECPoint Y = G.multiply(y).add(N.multiply(new BigInteger(1, w0)));
        
        byte[] publicShare = Y.getEncoded(true);
        byte[] verifierEvidence = computeHMAC(w1, X.getEncoded(true));
        
        // Store VerifierOutput for later use
        VerifierOutput verifierOutput = new VerifierOutput(publicShare, verifierEvidence);
        
        // Return Y and evidence M in Spake2PlusVerify
        return new Spake2PlusVerify(publicShare, verifierEvidence);
    }

    // Step 4: Prover verifies and generates final response
    public Spake2PlusVerifyResponse verifyAndGenerateFinalResponse(Spake2PlusVerify verify) 
            throws GeneralSecurityException {
        // Validate received point Y
        ECPoint Y = G.getCurve().decodePoint(verify.Y());
        if (!validatePoint(Y)) {
            throw new GeneralSecurityException("Invalid point Y received from Verifier");
        }

        // Calculate shared secrets
        ECPoint Z = Y.subtract(N.multiply(new BigInteger(1, w0))).multiply(x.multiply(h));
        ECPoint V = G.multiply(new BigInteger(1, w1)).multiply(y.multiply(h));

        // Compute shared secrets K, CK, SK
        byte[] transcript = computeTranscript(Z.getEncoded(true), V.getEncoded(true));
        deriveSharedSecrets(transcript);

        // Verify received evidence
        byte[] expectedEvidence = computeHMAC(sharedCK, "Verifier".getBytes(StandardCharsets.UTF_8));
        if (!Arrays.constantTimeAreEqual(expectedEvidence, verify.M())) {
            throw new GeneralSecurityException("Invalid verifier evidence");
        }

        // Generate prover evidence
        byte[] proverEvidence = computeHMAC(sharedCK, "Prover".getBytes(StandardCharsets.UTF_8));

        return new Spake2PlusVerifyResponse(proverEvidence);
    }

    // Final verification by Verifier
    public void finalVerification(byte[] proverEvidence) throws GeneralSecurityException {
        byte[] expectedEvidence = computeHMAC(sharedCK, "Prover".getBytes(StandardCharsets.UTF_8));
        if (!Arrays.constantTimeAreEqual(expectedEvidence, proverEvidence)) {
            throw new GeneralSecurityException("Invalid prover evidence");
        }
    }

    private void deriveSharedSecrets(byte[] transcript) throws GeneralSecurityException {
        byte[] secrets = computeHMAC(w0, transcript);
        // Split secrets into K, CK, and SK
        sharedK = Arrays.copyOfRange(secrets, 0, 16);
        sharedCK = Arrays.copyOfRange(secrets, 16, 32);
        sharedSK = Arrays.copyOfRange(secrets, 32, 48);
    }

    private byte[] deriveScryptKey(String password, byte[] salt, int n, int r, int p) {
        return SCrypt.generate(
            password.getBytes(StandardCharsets.UTF_8),
            salt,
            n, r, p,
            DERIVED_KEY_LENGTH
        );
    }

    private byte[] generateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    private BigInteger generateSecureScalar(BigInteger max) {
        BigInteger scalar;
        do {
            scalar = new BigInteger(max.bitLength(), secureRandom);
        } while (scalar.compareTo(max) >= 0 || scalar.equals(BigInteger.ZERO));
        return scalar;
    }

    private byte[] computeHMAC(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac hmac = Mac.getInstance("HmacSHA256");
        hmac.init(new SecretKeySpec(key, "HmacSHA256"));
        return hmac.doFinal(data);
    }

    private byte[] computeTranscript(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            totalLength += arr.length + 8; // 8 bytes for length encoding
        }
        
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            byte[] length = BigIntegers.asUnsignedByteArray(8, BigInteger.valueOf(arr.length));
            System.arraycopy(length, 0, result, offset, 8);
            offset += 8;
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    private static boolean validatePoint(ECPoint point) {
        return point != null && !point.isInfinity() && point.isValid();
    }
}
