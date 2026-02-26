# API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication Endpoints

### POST /auth/register
Register a new user account.

**Request Body:**
```json
{
  "username": "user@example.com",
  "salt": "base64_encoded_32_byte_salt",
  "passwordVerifier": "base64_pbkdf2_verifier"
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "User registered successfully",
  "userId": "550e8400-e29b-41d4-a716-446655440000",
  "salt": "base64_encoded_salt",
  "username": "user@example.com"
}
```

**Error Response (409 Conflict):**
```json
{
  "success": false,
  "error": "Username already exists"
}
```

---

### POST /auth/login
Complete challenge-response login and retrieve tokens.

**Request Body:**
```json
{
  "username": "user@example.com",
  "challengeId": "f6fd20d9-8b08-4b6d-b095-5ea81717065f",
  "challengeResponse": "base64_hmac_sha256_proof"
}
```

---

### POST /auth/login/challenge
Request one-time login challenge and salt.

**Request Body:**
```json
{
  "username": "user@example.com"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "challengeId": "f6fd20d9-8b08-4b6d-b095-5ea81717065f",
  "challenge": "base64_random_challenge",
  "salt": "base64_encoded_salt",
  "expiresIn": 300
}
```

**Error Response (401 Unauthorized):**
```json
{
  "success": false,
  "error": "Invalid username or password"
}
```

---

## Password Management Endpoints

All password endpoints use a hybrid transport envelope (`transport`) during normal operation. A plain JSON payload is only a compatibility fallback when transport is not initialized.

### POST /transport/init
Initialize a hybrid secure transport session for authenticated API calls.

**Headers:**
- `Authorization: Bearer <access_token>`
- `X-CSRF-Token: <csrf_token>`

**Request Body:**
```json
{
  "clientPqcPublicKey": "base64_ml_kem_public_key",
  "clientEcdhPublicKey": "base64_p256_public_key"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "sessionId": "a30de4d3-58db-4cd1-b6c5-af95f0ad5644",
  "serverEcdhPublicKey": "base64_p256_public_key",
  "pqcCiphertext": "base64_ml_kem_ciphertext",
  "expiresIn": 900,
  "algorithm": "ML-KEM-1024+ECDH-P256+HKDF-SHA256+AES-256-GCM"
}
```

---

### POST /passwords/add
Add or update an encrypted password entry.

**Request Body:**
```json
{
  "transport": {
    "sessionId": "a30de4d3-58db-4cd1-b6c5-af95f0ad5644",
    "iv": "base64_iv",
    "ciphertext": "base64_aes_gcm_encrypted_json_payload"
  }
}
```

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Password saved successfully",
  "passwordId": "660e8400-e29b-41d4-a716-446655440000"
}
```

**Response (200 OK) - When updating existing:**
```json
{
  "success": true,
  "message": "Password updated successfully",
  "passwordId": "660e8400-e29b-41d4-a716-446655440000"
}
```

---

### POST /passwords/get-all
Retrieve all encrypted passwords for a user.

**Request Body:**
```json
{
  "transport": {
    "sessionId": "a30de4d3-58db-4cd1-b6c5-af95f0ad5644",
    "iv": "base64_iv",
    "ciphertext": "base64_aes_gcm_encrypted_json_payload"
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "passwords": [
    {
      "passwordId": "660e8400-e29b-41d4-a716-446655440000",
      "siteUrl": "google.com",
      "siteUsername": "user@gmail.com",
      "encryptedPassword": "base64_encrypted_password",
      "iv": "base64_initialization_vector",
      "authTag": "base64_auth_tag",
      "pqc": {
        "active": true,
        "verified": true,
        "status": "verified"
      },
      "createdAt": "2024-01-01T00:00:00",
      "updatedAt": "2024-01-01T00:00:00"
    }
  ]
}
```

---

### POST /passwords/delete
Delete a password entry.

**Request Body:**
```json
{
  "transport": {
    "sessionId": "a30de4d3-58db-4cd1-b6c5-af95f0ad5644",
    "iv": "base64_iv",
    "ciphertext": "base64_aes_gcm_encrypted_json_payload"
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Password deleted successfully"
}
```

---

### POST /passwords/get-crypto-view
Get encrypted data view for transparency demonstration.

**Request Body:**
```json
{
  "transport": {
    "sessionId": "a30de4d3-58db-4cd1-b6c5-af95f0ad5644",
    "iv": "base64_iv",
    "ciphertext": "base64_aes_gcm_encrypted_json_payload"
  }
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "cryptoData": {
    "username": "user@example.com",
    "userId": "550e8400-e29b-41d4-a716-446655440000",
    "salt": "base64_salt",
    "masterPasswordHash": "base64_hash",
    "note": "This is the server-side view. Notice that passwords are encrypted.",
    "passwords": [
      {
        "siteUrl": "google.com",
        "siteUsername": "user@gmail.com",
        "encryptedPassword": "base64_encrypted_password_truncated...",
        "iv": "base64_iv",
        "authTag": "base64_auth_tag",
        "note": "Server stores only encrypted ciphertext - cannot decrypt without vault key"
      }
    ]
  }
}
```

---

## Health Check

### GET /api/health
Check if the API is running.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "service": "PQC Password Manager",
  "version": "1.0.0"
}
```

---

## Security Notes

### Zero-Knowledge Architecture
- Master password is **never** sent to the backend
- Vault key is derived client-side using PBKDF2 with 600,000 iterations
- Login uses challenge-response proof (HMAC-SHA256 over a one-time challenge)
- All password encryption/decryption happens in the browser
- Server only stores encrypted ciphertext and authentication metadata
- Password API payloads use hybrid transport sessions (ML-KEM + ECDH + AES-GCM) in addition to TLS

### Encryption Details
- **Algorithm:** AES-256-GCM
- **Key Derivation:** PBKDF2-HMAC-SHA256
- **Iterations:** 600,000
- **Salt:** Unique per user, 256 bits
- **IV:** Unique per password, 96 bits

### Post-Quantum Cryptography
- **Key Encapsulation:** ML-KEM-1024 (liboqs)
- **Digital Signatures:** ML-DSA-87 (liboqs)
- **Transport Session:** Hybrid ML-KEM-1024 + ECDH P-256 + HKDF-SHA256 + AES-256-GCM
- TLS cipher suite remains deployment-dependent; TLS-layer PQC requires a PQC-enabled TLS terminator/proxy.

---

## Error Codes

| Status Code | Meaning |
|------------|---------|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request - Missing or invalid parameters |
| 401 | Unauthorized - Invalid credentials |
| 404 | Not Found - Resource doesn't exist |
| 409 | Conflict - Resource already exists |
| 500 | Internal Server Error |

---

## Rate Limiting

Currently not implemented. For production:
- Implement rate limiting on authentication endpoints
- Add CAPTCHA for repeated failed login attempts
- Implement account lockout after multiple failures
