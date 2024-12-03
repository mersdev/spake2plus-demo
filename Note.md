# SPAKE2+ Implementation Notes

## Overview
SPAKE2+ is a password-authenticated key exchange protocol that allows two parties to establish a shared secret key based on a password, without exposing the password to offline dictionary attacks.

## Protocol Steps

### 1. Initial Setup
- Uses elliptic curve cryptography (secp256r1/NIST P-256)
- Requires two fixed points M and N on the curve
- Uses standardized scalar values for point generation:
  ```java
  mScalar = "886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12"
  nScalar = "8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"
  ```

### 2. Key Exchange Flow
1. **Verifier Initiation**
   - Generates random salt
   - Creates Scrypt configuration
   - Returns initialization parameters

2. **Prover Response**
   - Processes password with Scrypt
   - Generates random scalar x
   - Computes X = G * x + M * w0
   - Returns public share X

3. **Verifier Verification**
   - Validates received point X
   - Generates random scalar y
   - Computes Y = G * y + N * w0
   - Generates verification evidence
   - Returns Y and evidence

4. **Prover Final Verification**
   - Verifies Y point
   - Computes shared secrets
   - Generates final confirmation
   - Returns confirmation evidence

## Why Hardcoded Values?

### Security Considerations
1. **Nothing-Up-My-Sleeve Numbers**
   - M and N points are generated deterministically
   - Values are derived from well-known constants
   - Prevents backdoor insertion in point generation

2. **Unknown Discrete Logarithm**
   - No party should know log_G(M) or log_G(N)
   - Prevents protocol manipulation
   - Ensures security properties

3. **Standardization Benefits**
   - Interoperability between implementations
   - Verified by cryptographic community
   - Consistent security properties

### Implementation Details
1. **Point Generation**
   ```java
   M = G.multiply(mScalar)
   N = G.multiply(nScalar)
   ```
   - Uses curve's generator point G
   - Ensures points are on the curve
   - Maintains required security properties

2. **Validation**
   - Points must be:
     * Non-null
     * Non-infinity
     * Valid curve points
   - Implemented in validatePoint method

## Security Properties

### 1. Forward Secrecy
- Compromised password doesn't reveal past session keys
- Each session uses fresh random values x, y

### 2. Man-in-the-Middle Protection
- Authenticated key exchange
- Mutual authentication of both parties
- Protection against active attackers

### 3. Password Protection
- Password never transmitted
- Resistant to offline dictionary attacks
- Uses Scrypt for password hashing

## Best Practices

1. **Random Number Generation**
   - Use SecureRandom for scalars
   - Fresh values for each session
   - Proper entropy gathering

2. **Point Validation**
   - Always validate received points
   - Check for infinity and curve membership
   - Prevent small subgroup attacks

3. **Error Handling**
   - Clear error messages
   - Proper exception handling
   - No information leakage

## Model Classes

### Request/Response Models
1. **Spake2PlusRequest**
   - Salt for password hashing
   - Scrypt configuration parameters

2. **Spake2PlusResponse**
   - Prover's public share (X)
   - Protocol version information

3. **Spake2PlusVerify**
   - Verifier's public share (Y)
   - Verification evidence

4. **Spake2PlusVerifyResponse**
   - Final confirmation evidence
   - Session completion status

## Implementation Notes

1. **Initialization**
   - Static initialization block for curve parameters
   - Proper error handling during setup
   - Validation of generated points

2. **Service Methods**
   - Clear separation of protocol steps
   - Proper state management
   - Comprehensive error handling

3. **Security Considerations**
   - No sensitive data logging
   - Proper cleanup of sensitive values
   - Input validation at all steps
