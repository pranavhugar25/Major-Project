# PQC Password Manager - Security Analysis Document

**Document Version:** 1.0  
**Date:** February 25, 2026  
**Classification:** Security Critical - Internal Use Only  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Critical Security Issues](#2-critical-security-issues)
3. [High Severity Issues](#3-high-severity-issues)
4. [Medium Severity Issues](#4-medium-severity-issues)
5. [Security Gaps: Documentation vs Implementation](#5-security-gaps-documentation-vs-implementation)
6. [Strengths](#6-strengths)
7. [Threat Coverage Analysis](#7-threat-coverage-analysis)
8. [Recommendations](#8-recommendations)

---

## 1. Executive Summary

This document provides a comprehensive security analysis of the PQC Password Manager implementation. The application implements a **Zero-Knowledge Architecture** with **Post-Quantum Cryptography** intentions, but significant security gaps exist between the documented security claims and actual implementation.

### Security Posture Summary

| Aspect | Status |
|--------|--------|
| Overall Security Rating | **MEDIUM-LOW** |
| Critical Vulnerabilities | 3 |
| High Severity Issues | 3 |
| Medium Severity Issues | 3 |
| Cryptographic Implementation | Partially Complete |
| Zero-Knowledge Compliance | **FAILED** |

### Key Findings

The most critical finding is that **the master password is transmitted to the server in plaintext**, directly contradicting the zero-knowledge architecture claims. Additionally, the Post-Quantum Cryptography (PQC) implementation exists but is **not integrated into the actual encryption flow**, making it a non-functional security feature.

---

## 2. Critical Security Issues

### 2.1 Master Password Transmitted to Server in Plaintext

**Severity:** CRITICAL  
**CWE:** CWE-319 (Cleartext Transmission of Sensitive Information)  
**Location:** [`frontend/src/utils/api.js:250-254`](frontend/src/utils/api.js:250), [`backend/routes/auth.py:189-190`](backend/routes/auth.py:189)

#### Description

The master password is sent in plaintext to the server during both registration and login operations. This completely defeats the zero-knowledge architecture that the application claims to implement.

#### Evidence

**Frontend - Login Request:**
```javascript
// File: frontend/src/utils/api.js:250-254
login: async (username, masterPassword) => {
  const response = await api.post('/auth/login', {
    username,
    masterPassword  // ← Sent in plaintext!
  });
  return response.data;
}
```

**Backend - Login Handler:**
```python
# File: backend/routes/auth.py:189-190
username = (data.get("username") or "").strip()
master_password = data.get("masterPassword") or ""  # ← Received in plaintext!
```

**Backend - Registration Handler:**
```python
# File: backend/routes/auth.py:127
master_password = data.get("masterPassword") or ""  # ← Received in plaintext!
```

#### Impact

1. **Complete compromise of zero-knowledge claim** - Server possesses the plaintext master password
2. **Man-in-the-middle attacks** - If HTTPS is compromised, master passwords are exposed
3. **Server-side logging risk** - Plaintext passwords may appear in server logs
4. **Insider threat** - Server administrators can access user master passwords
5. **Legal/compliance violation** - Contradicts security documentation and promises to users

#### Remediation Required

The correct zero-knowledge flow should be:
1. Client derives key from master password using PBKDF2
2. Client encrypts a challenge or proves knowledge of derived key
3. Server only stores and verifies the password hash
4. **Master password must NEVER be transmitted to the server**

---

### 2.2 SessionStorage Token Storage Vulnerable to XSS

**Severity:** CRITICAL  
**CWE:** CWE-79 (Improper Neutralization of Input During Web Page Generation)  
**Location:** [`frontend/src/utils/api.js:129-143`](frontend/src/utils/api.js:129)

#### Description

Authentication tokens (access token, refresh token, CSRF token) are stored in `sessionStorage`, which is accessible to JavaScript and thus vulnerable to XSS attacks.

#### Evidence

```javascript
// File: frontend/src/utils/api.js:129-143
export const setAuthTokens = (tokenData) => {
  if (tokenData.access_token) {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, tokenData.access_token);  // ← XSS accessible
  }
  if (tokenData.refresh_token) {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, tokenData.refresh_token);  // ← XSS accessible
  }
  if (tokenData.csrf_token) {
    sessionStorage.setItem(CSRF_TOKEN_KEY, tokenData.csrf_token);  // ← XSS accessible
  }
};
```

#### Impact

1. **Token theft via XSS** - Any successful XSS injection can steal all tokens
2. **Account takeover** - Attackers can use stolen refresh tokens
3. **Persistent access** - Tokens persist until tab is closed

#### Note on Documentation

The codebase acknowledges this vulnerability in comments:
```javascript
// File: frontend/src/utils/api.js:14-15
/**
 * Current implementation uses sessionStorage which is vulnerable to XSS attacks.
 * For production, implement httpOnly cookies on the backend.
 */
```

However, no production mitigation has been implemented.

---

### 2.3 No Server-Side Key Verification

**Severity:** CRITICAL  
**Location:** [`backend/routes/auth.py:222-276`](backend/routes/auth.py:222)

#### Description

After successful login, the server only verifies that the provided master password produces the correct hash. There is no verification that the client can actually derive and use the vault key for encryption/decryption.

#### Evidence

```python
# File: backend/routes/auth.py:222-223
user = User.query.filter_by(username=username).first()
if not user or not verify_password(master_password, user.salt, user.master_password_hash):
    # Only verifies password hash - no key derivation proof
```

The server returns the salt to the client but never verifies:
1. That the client successfully derived the vault key
2. That the client can encrypt/decrypt test data
3. That subsequent operations use the correct key

#### Impact

1. **False authentication** - User could login with correct password hash but incorrect key derivation
2. **Silent vault corruption** - User won't be able to access their passwords but server shows "success"
3. **No key confirmation** - No proof-of-knowledge of the derived key

#### Remediation Required

Implement a key confirmation protocol:
1. Server generates a random challenge
2. Client encrypts challenge with derived vault key
3. Server verifies encryption (requires storing per-user public key or challenge-response)
4. Or: Client sends encrypted "known plaintext" for server to verify

---

## 3. High Severity Issues

### 3.1 PQC Implemented But Not Actively Used in Encryption Flow

**Severity:** HIGH  
**Location:** [`backend/utils/pqc.py`](backend/utils/pqc.py), [`frontend/src/utils/crypto.js`](frontend/src/utils/crypto.js)

#### Description

Post-Quantum Cryptography (ML-KEM-1024 and ML-DSA-87) is fully implemented in the backend but is **not integrated into the actual encryption flow**. The frontend only uses AES-256-GCM.

#### Evidence

**PQC Implementation Exists:**
```python
# File: backend/utils/pqc.py:57-110
class MLKEM1024:
    """ML-KEM-1024 wrapper."""
    ALGORITHM = "ML-KEM-1024"
    
    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        # Implemented
        
    @staticmethod
    def encapsulate(public_key_b64: str) -> KEMResult:
        # Implemented
        
    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        # Implemented
```

**But Frontend Uses Only AES-256-GCM:**
```javascript
// File: frontend/src/utils/crypto.js:93-131
export const encryptPassword = async (plaintext, vaultKeyBase64) => {
  // Uses AES-256-GCM only - no PQC
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    new TextEncoder().encode(plaintext)
  );
};
```

**PQC is only available as library, not actively used:**
- No ML-KEM key exchange for session key establishment
- No ML-DSA signatures for authenticity
- PQC functions are exported but never called in the encryption/decryption flow

#### Impact

1. **False sense of security** - Users believe they're protected by PQC
2. **Quantum vulnerability** - Data is only protected by classical AES-256
3. **Documentation inconsistency** - Architecture docs claim PQC protection

#### Remediation Required

1. Implement hybrid encryption: Use PQC (ML-KEM) to exchange session keys
2. Use ML-DSA for signing password entries
3. Or at minimum, document that PQC is "available but not active"

---

### 3.2 In-Memory Token Blacklist (Not Scalable/Production-Ready)

**Severity:** HIGH  
**Location:** [`backend/utils/auth.py:26`](backend/utils/auth.py:26)

#### Description

Token blacklist is stored in-memory, which is not scalable and loses all data on server restart.

#### Evidence

```python
# File: backend/utils/auth.py:26
# In production, this should be backed by Redis or another shared datastore.
token_blacklist: Dict[str, float] = {}  # ← In-memory only!
```

```python
# File: backend/app.py:110
storage_uri=("memory://" if testing else os.environ.get("RATELIMIT_STORAGE_URL", "memory://")),
```

#### Impact

1. **Lost blacklisted tokens** - Server restart clears blacklist
2. **No horizontal scaling** - Multiple server instances don't share blacklist
3. **Security bypass** - Users can reuse tokens after restart even if logged out
4. **Rate limiting bypass** - Same limitation applies to rate limiting

#### Note

The code contains a comment acknowledging this is not production-ready:
```python
# File: backend/utils/auth.py:25
# In production, this should be backed by Redis or another shared datastore.
```

---

### 3.3 No Rate Limiting on All Endpoints

**Severity:** HIGH  
**Location:** [`backend/app.py:56-72`](backend/app.py:56)

#### Description

While rate limiting is configured, it uses in-memory storage and is applied selectively. Some endpoints may not have adequate protection.

#### Evidence

```python
# File: backend/app.py:56-72
def _apply_endpoint_rate_limits(app: Flask, limiter: Limiter) -> None:
    endpoint_limits = {
        "auth.register": "3 per 15 minute",
        "auth.login": "5 per 15 minute",
        # ... limited list
    }
```

Issues:
1. Rate limiting uses in-memory storage (see issue 3.2)
2. Only specific endpoints have custom limits
3. Default limits may be too permissive: `"500 per day", "100 per hour"` at line 109

---

## 4. Medium Severity Issues

### 4.1 No Vault Key Confirmation on Login

**Severity:** MEDIUM  
**Location:** [`backend/routes/auth.py:260-276`](backend/routes/auth.py:260), [`frontend/src/components/Login.js:29-37`](frontend/src/components/Login.js:29)

#### Description

After login, there is no cryptographic proof that the client has correctly derived the vault key. The server only verifies the password hash, not key derivation capability.

#### Evidence

**Frontend - Derives key but no verification:**
```javascript
// File: frontend/src/components/Login.js:29-37
// Derive vault key client-side
const vaultKey = await deriveVaultKey(masterPassword, response.salt);

// Pass user data and vault key to parent - NO VERIFICATION
onLoginSuccess({
  userId: response.userId,
  username: response.username,
  salt: response.salt
}, vaultKey);
```

**Backend - No key confirmation:**
```python
# File: backend/routes/auth.py:260-276
# Returns success without verifying key derivation
return (
    jsonify({
        "success": True,
        "message": "Login successful",
        "userId": str(user.user_id),
        "salt": user.salt,  # ← Sends salt but never verifies key
        ...
    }),
    200,
)
```

#### Impact

1. **Silent failures** - User may have correct password but incorrect key derivation
2. **No recovery path** - User won't know vault is inaccessible until trying to decrypt
3. **Confusion** - "Successful login" but passwords inaccessible

---

### 4.2 Memory Clearing Not Truly Secure in JavaScript

**Severity:** MEDIUM  
**Location:** [`frontend/src/utils/crypto.js:15-19`](frontend/src/utils/crypto.js:15)

#### Description

JavaScript does not provide true memory control. The `secureZeroize` function only overwrites the array, but the original data may persist in memory due to garbage collection timing and JavaScript engine optimizations.

#### Evidence

```javascript
// File: frontend/src/utils/crypto.js:15-19
export const secureZeroize = (data) => {
  if (data && typeof data.fill === 'function') {
    data.fill(0);  // ← Only overwrites the reference, not underlying memory
  }
};
```

```python
# File: backend/utils/crypto.py:14-23
def secure_zeroize(data: bytearray) -> None:
    """Securely clear sensitive data from memory"""
    if data:
        for i in range(len(data)):
            data[i] = 0  # ← Python GC may keep copies
```

#### Impact

1. **Residual data** - Keys may persist in memory longer than intended
2. **Cold boot attacks** - Less relevant for web apps but still a theoretical risk
3. **Swap file exposure** - Memory may be written to disk

#### Note

This is a known limitation of JavaScript and Python. The implementation follows best practices but cannot guarantee complete memory clearing.

---

### 4.3 Database Not Encrypted at Rest in Development

**Severity:** MEDIUM  
**Location:** [`backend/app.py:85-86`](backend/app.py:85)

#### Description

The default SQLite database has no encryption at rest. Password data (encrypted) and password hashes are stored in plaintext on disk.

#### Evidence

```python
# File: backend/app.py:85-86
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///pqc_password_manager.db"  # ← No encryption!
)
```

Stored data includes:
- User IDs and usernames
- Master password hashes (not encrypted)
- Salts (in plaintext)
- Encrypted password entries
- IVs and auth tags

#### Impact

1. **Database theft** - Stolen database file reveals all user data
2. **Password hash exposure** - While hashed, salts and hashes are exposed
3. **Encrypted data exposure** - Encrypted passwords are readable
4. **Metadata leakage** - Access patterns, usernames, site URLs visible

#### Mitigation in Place

The architecture documentation mentions "Database Encryption: Encrypted at rest (production)" as a security layer (see [`docs/ARCHITECTURE.md:142`](docs/ARCHITECTURE.md:142)), but this is not implemented.

---

## 5. Security Gaps: Documentation vs Implementation

This section highlights where the implementation fails to meet the documented security claims.

### 5.1 Zero-Knowledge Architecture Claim vs Reality

| Documentation Claim | Actual Implementation | Gap Severity |
|---------------------|---------------------|--------------|
| "Zero-Knowledge: All encryption/decryption happens in the browser" (Frontend CryptoView comments) | Master password sent to server in plaintext | **CRITICAL** |
| "Server cannot decrypt user passwords" | Server receives master password directly | **CRITICAL** |
| "Client-side encryption" | Client-side encryption exists, but password transmission defeats purpose | **CRITICAL** |

#### Documentation Evidence

From [`frontend/src/components/Login.js:66`](frontend/src/components/Login.js:66):
```javascript
<p className="auth-subtitle">Zero-Knowledge Password Manager</p>
```

From [`docs/ARCHITECTURE.md:5`](docs/ARCHITECTURE.md:5):
> The PQC Password Manager implements a **Zero-Knowledge Architecture**

From [`docs/ARCHITECTURE.md:40-68`](docs/ARCHITECTURE.md:40):
```
User                    Client                    Server
  │                       │                         │
  │                       │ Hash master password    │  ← NOT CORRECT
  │                       │ POST /auth/register     │
  │                       │ {username, hash}        │  ← Actually sends plaintext
```

#### Implementation Reality

```python
# backend/routes/auth.py:189-190
master_password = data.get("masterPassword") or ""  # ← Plaintext received!
```

---

### 5.2 Rate Limiting Claim vs Implementation

| Documentation Claim | Actual Implementation | Gap Severity |
|---------------------|---------------------|--------------|
| Architecture doc lists "Rate limiting" as production recommendation | Rate limiting is implemented but uses in-memory storage | **HIGH** |
| "Brute-force protection" (line 214) | In-memory rate limiting that resets on restart | **MEDIUM** |

#### Documentation Evidence

From [`docs/ARCHITECTURE.md:205`](docs/ARCHITECTURE.md:205):
```markdown
## Security Features
...
"Rate limiting",
```

From [`backend/app.py:153`](backend/app.py:153):
```python
"rate_limiting": True,  # ← Claimed as enabled
```

---

### 5.3 PQC Active Status vs Implementation

| Documentation Claim | Actual Implementation | Gap Severity |
|---------------------|---------------------|--------------|
| "Post-Quantum Cryptography" (Architecture, Homepage) | PQC library exists but not used in encryption | **CRITICAL** |
| "ML-KEM-1024: Key encapsulation mechanism" (Architecture) | No key encapsulation in actual flow | **HIGH** |
| "ML-DSA-87: Digital signature algorithm" (Architecture) | No signatures used | **HIGH** |

#### Documentation Evidence

From [`docs/ARCHITECTURE.md:115-136`](docs/ARCHITECTURE.md:115):
```markdown
### Layer 2: Post-Quantum Protection
- **ML-KEM (Kyber):** Key encapsulation mechanism
- **ML-DSA (Dilithium):** Digital signature algorithm
```

From [`backend/utils/pqc.py:16-20`](backend/utils/pqc.py:16):
```python
# Algorithms:
# - ML-KEM-1024 (KEM, NIST Level 5)
# - ML-DSA-87 (signature, NIST Level 5)
```

But these are never called in the encryption/decryption flow.

---

### 5.4 Database Encryption Claim

| Documentation Claim | Actual Implementation | Gap Severity |
|---------------------|---------------------|--------------|
| "Database Encryption: Encrypted at rest (production)" | SQLite with no encryption | **MEDIUM** |

---

## 6. Strengths

Despite the critical issues, the implementation has several security strengths.

### 6.1 Strong PBKDF2 Key Derivation

**Implementation:** [`backend/utils/crypto.py:40-63`](backend/utils/crypto.py:40), [`frontend/src/utils/crypto.js:45-81`](frontend/src/utils/crypto.js:45)

| Parameter | Value | Assessment |
|-----------|-------|------------|
| Algorithm | PBKDF2-HMAC-SHA256 | ✅ Industry Standard |
| Iterations | 600,000 | ✅ Exceeds OWASP 2024 recommendation (600k) |
| Salt Length | 256 bits (32 bytes) | ✅ Sufficient |
| Derived Key | 256 bits | ✅ AES-256 compatible |

```python
# backend/utils/crypto.py:54-61
# PBKDF2 with 600,000 iterations (OWASP recommendation for 2024)
password_hash = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    salt_bytes,
    iterations=600000,  # ✅ Strong
    dklen=32
)
```

```javascript
// frontend/src/utils/crypto.js:59-72
// Derive 256-bit key using PBKDF2 with 600,000 iterations
const vaultKey = await crypto.subtle.deriveKey(
  {
    name: 'PBKDF2',
    salt: saltBytes,
    iterations: 600000,  // ✅ Strong
    hash: 'SHA-256'
  },
  keyMaterial,
  { name: 'AES-GCM', length: 256 },
  true,
  ['encrypt', 'decrypt']
);
```

---

### 6.2 AES-256-GCM Authenticated Encryption

**Implementation:** [`frontend/src/utils/crypto.js:93-181`](frontend/src/utils/crypto.js:93)

| Parameter | Value | Assessment |
|-----------|-------|------------|
| Algorithm | AES-256-GCM | ✅ Industry Gold Standard |
| IV Length | 96 bits (12 bytes) | ✅ Recommended for GCM |
| Auth Tag | 128 bits | ✅ Strong integrity |
| Key Derivation | PBKDF2 | ✅ Proper separation |

```javascript
// Encrypt
const iv = crypto.getRandomValues(new Uint8Array(12));  // 96-bit IV
const encrypted = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv: iv },
  key,
  new TextEncoder().encode(plaintext)
);

// Decrypt - auth tag verified by Web Crypto API
const decrypted = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv: iv },
  key,
  encryptedData
);
```

---

### 6.3 Unique Salts and IVs

**Implementation:** [`backend/utils/crypto.py:26-37`](backend/utils/crypto.py:26), [`frontend/src/utils/crypto.js:95-96`](frontend/src/utils/crypto.js:95)

- ✅ Each user has unique 256-bit salt
- ✅ Each password encryption uses unique 96-bit IV
- ✅ Cryptographically secure random generation (`secrets.token_bytes`, `crypto.getRandomValues`)

```python
# backend/utils/crypto.py:26-37
def generate_salt(length: int = 32) -> str:
    salt_bytes = secrets.token_bytes(length)  # Cryptographically secure
    return base64.b64encode(salt_bytes).decode('utf-8')
```

```javascript
// frontend/src/utils/crypto.js:95-96
const iv = crypto.getRandomValues(new Uint8Array(12));  // Unique per encryption
```

---

### 6.4 CSRF Protection

**Implementation:** [`backend/utils/auth.py:160-168`](backend/utils/auth.py:160), [`frontend/src/utils/api.js:46-50`](frontend/src/utils/api.js:46)

- ✅ CSRF tokens generated per session
- ✅ Token validation on state-changing operations
- ✅ Header-based token transmission (`X-CSRF-Token`)

```python
# backend/utils/auth.py:160-168
def validate_csrf_token(payload: Dict[str, Any]) -> None:
    if request.method in SAFE_HTTP_METHODS:
        return
    expected = payload.get("csrf")
    provided = request.headers.get(CSRF_HEADER)
    if not expected or not provided:
        raise AuthError("Missing CSRF token", 403)
    if not secrets.compare_digest(str(expected), str(provided)):
        raise AuthError("Invalid CSRF token", 403)
```

```javascript
// frontend/src/utils/api.js:46-50
const method = (config.method || 'GET').toUpperCase();
if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    const csrfToken = sessionStorage.getItem(CSRF_TOKEN_KEY);
    if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
    }
}
```

---

### 6.5 Brute-Force Protection

**Implementation:** [`backend/routes/auth.py:32-96`](backend/routes/auth.py:32)

| Protection | Value | Assessment |
|------------|-------|------------|
| Max Failed Attempts | 10 | ✅ Reasonable |
| Lockout Duration | 15 minutes | ✅ Appropriate |
| Attempt Window | 15 minutes | ✅ Prevents mass attempts |
| Timing-safe comparison | ✅ `secrets.compare_digest` | |

```python
# backend/routes/auth.py:32-36
# Brute-force protections.
MAX_FAILED_ATTEMPTS = 10
LOCKOUT_DURATION_SECONDS = 15 * 60
ATTEMPT_WINDOW_SECONDS = 15 * 60

# backend/routes/auth.py:79
# Uses timing-safe comparison
return secrets.compare_digest(computed_hash, stored_hash)
```

---

### 6.6 Audit Logging

**Implementation:** [`backend/utils/audit.py`](backend/utils/audit.py)

Security events logged:
- Registration (success/failure)
- Login (success/failure/blocked)
- Logout
- Token operations

```python
# backend/routes/auth.py:228-237
log_security_event(
    "login",
    success=False,
    username=username,
    ip_address=ip_addr,
    details={
        "remaining_attempts": remaining_attempts,
        "locked": status_code == 429,
    },
)
```

---

### 6.7 Security Headers

**Implementation:** [`backend/app.py:122-137`](backend/app.py:122)

| Header | Value |
|--------|-------|
| X-Content-Type-Options | nosniff |
| X-Frame-Options | DENY |
| Referrer-Policy | no-referrer |
| Permissions-Policy | Restrictive |
| Cross-Origin-Opener-Policy | same-origin |
| Cross-Origin-Resource-Policy | same-site |
| Content-Security-Policy | Restrictive |
| Strict-Transport-Security | max-age=31536000 (production) |

```python
# backend/app.py:122-137
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # ... additional headers
```

---

## 7. Threat Coverage Analysis

### 7.1 What's Protected (As Documented)

| Threat | Protection | Status |
|--------|------------|--------|
| Man-in-the-Middle | HTTPS + TLS | ✅ Implemented |
| Server Breaches | Zero-Knowledge | ❌ **NOT IMPLEMENTED** (password sent to server) |
| Database Leaks | Encrypted data | ⚠️ Partial (data encrypted, but DB not at rest) |
| Quantum Attacks | PQC | ❌ **NOT IMPLEMENTED** (library exists but unused) |
| Rainbow Tables | Unique salts | ✅ Implemented |
| Brute Force | PBKDF2 600k | ✅ Implemented |
| CSRF Attacks | CSRF tokens | ✅ Implemented |
| XSS Token Theft | sessionStorage | ❌ **VULNERABLE** |

### 7.2 What's NOT Protected (Actual Gaps)

| Gap | Severity | File Location |
|-----|----------|---------------|
| Master password plaintext transmission | CRITICAL | [`frontend/src/utils/api.js:250`](frontend/src/utils/api.js:250), [`backend/routes/auth.py:189`](backend/routes/auth.py:189) |
| XSS token theft via sessionStorage | CRITICAL | [`frontend/src/utils/api.js:129`](frontend/src/utils/api.js:129) |
| No vault key verification | CRITICAL | [`backend/routes/auth.py:222`](backend/routes/auth.py:222) |
| PQC not in encryption flow | HIGH | [`backend/utils/pqc.py`](backend/utils/pqc.py) unused |
| In-memory token blacklist | HIGH | [`backend/utils/auth.py:26`](backend/utils/auth.py:26) |
| In-memory rate limiting | HIGH | [`backend/app.py:110`](backend/app.py:110) |
| No key confirmation proof | MEDIUM | [`frontend/src/components/Login.js:29`](frontend/src/components/Login.js:29) |
| JS memory clearing limitations | MEDIUM | [`frontend/src/utils/crypto.js:15`](frontend/src/utils/crypto.js:15) |
| DB not encrypted at rest | MEDIUM | [`backend/app.py:85`](backend/app.py:85) |

---

## 8. Recommendations

### Priority 1: Critical - Fix Master Password Transmission

**Issue:** Master password sent to server in plaintext  
**Files:** [`frontend/src/utils/api.js`](frontend/src/utils/api.js), [`backend/routes/auth.py`](backend/routes/auth.py)

**Recommendations:**

1. **Implement SRP (Secure Remote Password) or similar zero-knowledge proof:**
   - Server stores only password verifier (not hash)
   - Client proves knowledge without sending password
   - Use OPRF (Oblivious Pseudorandom Function) for quantum resistance

2. **Alternative: Challenge-Response Protocol:**
   - Server sends random challenge
   - Client encrypts challenge with derived vault key
   - Server verifies (requires storing per-user public key)

3. **Immediate Actions:**
   - Remove `masterPassword` field from API requests
   - Change login flow to only send username, derive key locally
   - Update documentation to reflect actual architecture

---

### Priority 2: High - Implement httpOnly Cookies

**Issue:** Tokens stored in sessionStorage vulnerable to XSS  
**Files:** [`frontend/src/utils/api.js`](frontend/src/utils/api.js), [`backend/routes/auth.py`](backend/routes/auth.py)

**Recommendations:**

1. **Backend changes:**
   - Set tokens as `httpOnly`, `Secure`, `SameSite=Strict` cookies
   - Implement token refresh that returns new cookies
   - Add CSRF token in separate cookie or response header

2. **Frontend changes:**
   - Remove sessionStorage token storage
   - Configure axios to send credentials
   - Handle 401 by redirecting to login

3. **Implementation reference:**
   ```python
   # Set cookie (backend)
   response.set_cookie(
       'pqc_access_token',
       access_token,
       httponly=True,
       secure=True,
       samesite='Strict',
       expires=expiry
   )
   ```

---

### Priority 3: High - Activate PQC in Encryption Flow

**Issue:** PQC implemented but not used  
**Files:** [`backend/utils/pqc.py`](backend/utils/pqc.py), [`frontend/src/utils/crypto.js`](frontend/src/utils/crypto.js)

**Recommendations:**

1. **Hybrid Encryption Implementation:**
   - Generate ML-KEM keypair per session
   - Use ML-KEM to exchange session key
   - Use AES-256-GCM for actual encryption (hybrid is stronger)
   - Sign password entries with ML-DSA

2. **User Key Storage:**
   - Store ML-KEM public key on server
   - Client generates keypair, sends public key
   - Use public key to encapsulate session key

3. **Graceful Degradation:**
   - Detect PQC availability
   - Fall back to classical-only if PQC unavailable
   - Log warning when PQC not active

---

### Priority 4: High - Production-Ready Token/Blacklist Storage

**Issue:** In-memory token blacklist  
**Files:** [`backend/utils/auth.py`](backend/utils/auth.py), [`backend/app.py`](backend/app.py)

**Recommendations:**

1. **Implement Redis for token storage:**
   ```python
   # production config
   RATELIMIT_STORAGE_URL = "redis://localhost:6379"
   token_blacklist stored in Redis
   ```

2. **Use Redis for rate limiting:**
   - Already supported by Flask-Limiter
   - Share across multiple server instances
   - Persist across restarts

3. **Alternative: Database storage:**
   - If Redis unavailable, use database
   - Add index on expiry time for cleanup

---

### Priority 5: Medium - Add Key Confirmation Proof

**Issue:** No verification that client correctly derived vault key  
**Files:** [`frontend/src/components/Login.js`](frontend/src/components/Login.js), [`backend/routes/auth.py`](backend/routes/auth.py)

**Recommendations:**

1. **Challenge-Response Protocol:**
   - Server stores user's public key (from PQC keypair)
   - On login, server sends random challenge
   - Client encrypts challenge with vault key
   - Server verifies or returns error

2. **Simplified: Known Plaintext Test:**
   - Client encrypts known string with vault key
   - Server stores this encrypted test vector
   - Client decrypts on login, server verifies

3. **Document Limitation:**
   - If not implementing, clearly document that login ≠ vault accessibility
   - Add warning when first decrypting passwords

---

### Priority 6: Medium - Database Encryption at Rest

**Issue:** SQLite database has no encryption  
**Files:** [`backend/app.py`](backend/app.py)

**Recommendations:**

1. **Development:**
   - Use SQLCipher for SQLite encryption
   - Or document that dev DB is unencrypted

2. **Production:**
   - Use PostgreSQL with TDE (Transparent Data Encryption)
   - Or use SQLCipher with key from environment
   - Consider column-level encryption for sensitive fields

3. **Quick Win:**
   - At minimum, encrypt password_hash column
   - Use application's existing key derivation

---

## Summary

| Priority | Issue | Severity | Effort |
|----------|-------|----------|--------|
| 1 | Fix master password transmission | CRITICAL | High |
| 2 | Implement httpOnly cookies | CRITICAL | Medium |
| 3 | Activate PQC in encryption flow | HIGH | High |
| 4 | Production-ready token storage | HIGH | Medium |
| 5 | Add key confirmation proof | MEDIUM | Medium |
| 6 | Database encryption at rest | MEDIUM | Medium |

---

## Appendix A: File Reference Index

| File | Purpose | Security Relevance |
|------|---------|-------------------|
| [`backend/routes/auth.py`](backend/routes/auth.py:1) | Authentication endpoints | CRITICAL: Password handling |
| [`frontend/src/utils/api.js`](frontend/src/utils/api.js:1) | API client | CRITICAL: Token storage |
| [`frontend/src/utils/crypto.js`](frontend/src/utils/crypto.js:1) | Client crypto | CRITICAL: Encryption |
| [`backend/utils/pqc.py`](backend/utils/pqc.py:1) | PQC implementation | HIGH: Unused |
| [`backend/utils/auth.py`](backend/utils/auth.py:1) | JWT handling | HIGH: Token blacklist |
| [`backend/app.py`](backend/app.py:1) | Flask app | MEDIUM: Rate limiting |
| [`backend/models/database.py`](backend/models/database.py:1) | Database models | MEDIUM: Encryption |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md:1) | Architecture docs | Documentation gaps |

---

## Appendix B: Security Checklist

- [ ] **CRITICAL:** Remove master password from API requests
- [ ] **CRITICAL:** Implement zero-knowledge login protocol
- [ ] **CRITICAL:** Switch to httpOnly cookies for tokens
- [ ] **CRITICAL:** Add vault key verification
- [ ] **HIGH:** Integrate PQC into encryption flow
- [ ] **HIGH:** Implement Redis for token/rate limit storage
- [ ] **MEDIUM:** Add key confirmation proof
- [ ] **MEDIUM:** Enable database encryption
- [ ] **MEDIUM:** Add production security documentation

---

*End of Security Analysis Document*
