# Security Analysis: PQC Password Manager

**Document Version:** 1.0  
**Analysis Date:** 2026-02-28  
**Classification:** Confidential - Security Assessment

---

## 1. Executive Summary

This document provides a comprehensive security analysis of the PQC Password Manager implementation, comparing the documented architecture and security claims against the actual code implementation.

### Overall Security Posture: **CRITICAL RISK**

The implementation has **fundamental architectural flaws** that completely undermine its core security claims. Despite marketing itself as a "Zero-Knowledge Password Manager" with "Post-Quantum Cryptography," the system violates its most fundamental security promises:

| Aspect | Status | Rating |
|--------|--------|--------|
| Zero-Knowledge Architecture | ❌ **VIOLATED** | Critical |
| Password Handling | ❌ **INSECURE** | Critical |
| PAKE Implementation | ❌ **FAKE** | Critical |
| JWT Security | ⚠️ **WEAK** | High |
| Session Management | ⚠️ **INCOMPLETE** | Medium |
| PQC Implementation | ✅ **REAL** | Good |

**Critical Finding:** The master password is transmitted in **plain text** to the server, directly contradicting the documented zero-knowledge architecture. This makes the entire system insecure regardless of any client-side encryption.

---

## 2. Documentation vs. Implementation Comparison

### 2.1 Claims vs. Reality

| Documentation Claim | Implementation Reality | Status |
|-------------------|----------------------|--------|
| "Your master password never leaves your device in plain text" (SECURITY.md line 9) | Password sent in plain text via `masterPassword` field in API requests | ❌ **CONTRADICTS** |
| "Key Derivation (Client-Side Only)" (SECURITY.md line 16) | Server performs PBKDF2 hashing in `backend/utils/crypto.py` lines 58-81 | ❌ **CONTRADICTS** |
| "Zero-knowledge data handling" (ARCHITECTURE.md line 29) | Server stores password hash enabling offline brute force | ❌ **CONTRADICTS** |
| "SPAKE2 for PAKE authentication" (auth.py line 97) | Uses SHA256(password+salt) - NOT real SPAKE2 | ❌ **FALSE CLAIM** |
| "HTTPS/TLS 1.3 for encrypted communication" (ARCHITECTURE.md line 134) | No HTTPS enforcement visible in code | ⚠️ **MISSING** |
| "OPRF" mentioned in architecture | Not implemented | ❌ **MISSING** |

### 2.2 Authentication Flow Comparison

**Documented Flow (ARCHITECTURE.md lines 42-68):**
```
User → Client: Enter credentials
Client: Generate salt, Derive vault key (PBKDF2), Hash master password
Client → Server: POST /auth/register {username, hash}
Server: Store user, Store salt, Store hash
```

**Actual Flow (backend/routes/auth.py lines 46-131):**
```
User → Client: Enter master password
Client → Server: POST /auth/register {username, masterPassword: "plain_text_password"}
Server: Receives plain text password!
Server: Generates salt, PBKDF2 hash (600k iterations), SHA256 "SPAKE2 verifier"
Server: Stores {username, master_password_hash, salt, spake2_verifier}
```

---

## 3. Security Strengths

Despite the critical weaknesses, the implementation has several positive security features:

### 3.1 Cryptographic Primitives

| Feature | Implementation | Compliance |
|---------|---------------|------------|
| **PQC Algorithms** | ML-KEM-1024, ML-DSA-87 via `liboqs-python` and `noble-post-quantum` | ✅ NIST Standard |
| **PBKDF2 Iterations** | 600,000 iterations (backend/utils/crypto.py line 77) | ✅ OWASP 2024 |
| **AES-256-GCM** | Client-side encryption for stored passwords | ✅ NIST Approved |
| **Salt Generation** | 256-bit random via `secrets.token_bytes(32)` | ✅ Secure |
| **IV Generation** | 96-bit random for GCM (backend/utils/crypto.py line 112 equivalent) | ✅ NIST Rec. |

### 3.2 Authentication Security

| Feature | Implementation | Compliance |
|---------|---------------|------------|
| **JWT Expiration** | Access: 15 min, Refresh: 1 day (auth.py lines 15-16) | ✅ Good |
| **Rate Limiting** | 200/day, 50/hour (docs/SECURITY.md line 178) | ✅ OWASP |
| **Account Lockout** | 5 failed attempts → 5 min lockout (auth.py lines 21-22) | ✅ Good |
| **SQL Injection** | SQLAlchemy ORM with parameterized queries | ✅ Protected |
| **XSS Prevention** | React auto-escapes content | ✅ Protected |
| **Constant-time Compare** | `secrets.compare_digest()` used (auth.py line 219) | ✅ Timing Safe |

### 3.3 Code Evidence of Strengths

**Real PQC Implementation** - `backend/utils/pqc.py` and `backend/utils/crypto.py` lines 109-191:
```python
# Uses liboqs-python for real ML-KEM-1024 and ML-DSA-87
def generate_kyber_keypair() -> Tuple[str, str]:
    return PQCKeyManager.generate_kyber_keypair()
```

**OWASP-Compliant PBKDF2** - `backend/utils/crypto.py` lines 70-79:
```python
password_hash = hashlib.pbkdf2_hmac(
    'sha256',
    password.encode('utf-8'),
    salt_bytes,
    iterations=600000,  # OWASP 2024 recommendation
    dklen=32
)
```

---

## 4. Critical Security Weaknesses

### 4.1 ZERO-KNOWLEDGE VIOLATION (Critical)

**Issue:** Master password transmitted in plain text to server

**Evidence:**
- [`frontend/src/utils/api.js:180-193`](frontend/src/utils/api.js:180): `register()` sends `masterPassword` in payload
- [`frontend/src/utils/api.js:202-206`](frontend/src/utils/api.js:202): `login()` sends `masterPassword` in payload  
- [`backend/routes/auth.py:55-56`](backend/routes/auth.py:55): Server receives `master_password = data.get('masterPassword')`
- [`backend/routes/auth.py:175-176`](backend/routes/auth.py:175): Same issue in login

**Risk Level:** 🔴 **CRITICAL**

**Impact:**
- Network observers (ISPs, WiFi attackers, MITM) can capture master password
- Server administrators have access to plain text passwords
- Logs may contain plain text passwords
- Completely undermines zero-knowledge claim

**Recommendation:**
- Implement client-side password hashing (PBKDF2) BEFORE sending to server
- Use SRP (Secure Remote Password) or full SPAKE2 for authentication
- Send only verifier, never the password

---

### 4.2 FAKE SPAKE2 IMPLEMENTATION (Critical)

**Issue:** Claims to use SPAKE2 PAKE but uses simple SHA256 hashing

**Evidence:**
- [`backend/utils/spake2_pake.py:211-232`](backend/utils/spake2_pake.py:211):
```python
def generate_password_verifier(password: str) -> Tuple[str, str]:
    salt = secrets.token_bytes(32)
    verifier_input = password.encode('utf-8') + salt
    verifier = hashlib.sha256(verifier_input).digest()  # NOT SPAKE2!
    return base64.b64encode(verifier).decode('utf-8'), ...
```

- [`backend/utils/spake2_pake.py:235-249`](backend/utils/spake2_pake.py:235):
```python
def compute_verifier(password: str, salt: str) -> str:
    salt_bytes = base64.b64decode(salt)
    verifier_input = password.encode('utf-8') + salt_bytes
    verifier = hashlib.sha256(verifier_input).digest()  # Single SHA256!
    return base64.b64encode(verifier).decode('utf-8')
```

**Comparison with Real SPAKE2:**
| Aspect | Real SPAKE2 | This Implementation |
|--------|-------------|---------------------|
| Protocol | Multiple round-trip messages | Single hash computation |
| Cryptography | Elliptic curve + password | Simple SHA256 |
| Forward Secrecy | Yes | No |
| Offline Attack | Resistant | Vulnerable |

**Risk Level:** 🔴 **CRITICAL**

**Impact:**
- Anyone with database access can perform offline brute force
- No protection against rainbow tables (though salts help)
- Not a true PAKE - provides false sense of security

---

### 4.3 SERVER-SIDE PASSWORD HASHING (Critical)

**Issue:** Password hashing occurs on server, violating zero-knowledge architecture

**Evidence:**
- [`backend/routes/auth.py:99-100`](backend/routes/auth.py:99):
```python
# Hash the master password (for backwards compatibility)
master_password_hash = hash_password(master_password, salt)
```

- [`backend/utils/crypto.py:58-81`](backend/utils/crypto.py:58):
```python
def hash_password(password: str, salt: str) -> str:
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),  # Server has plain text password!
        salt_bytes,
        iterations=600000,
        dklen=32
    )
```

**Risk Level:** 🔴 **CRITICAL**

**Impact:**
- Server learns the master password
- If server is compromised, all master passwords are exposed
- Cannot claim zero-knowledge - server CAN authenticate users directly
- Enables mass password recovery attacks on database breach

---

### 4.4 DATABASE STORES PASSWORD HASH (High)

**Issue:** Password hash stored in database enables offline brute force attacks

**Evidence:**
- [`backend/routes/auth.py:103-110`](backend/routes/auth.py:103):
```python
new_user = User(
    user_id=str(uuid.uuid4()),
    username=username,
    master_password_hash=master_password_hash,  # Stored!
    salt=salt,
    spake2_verifier=spake2_verifier,  # Also stored!
    spake2_salt=spake2_salt
)
```

- Database schema (ARCHITECTURE.md lines 148-156):
```sql
CREATE TABLE users (
    master_password_hash VARCHAR(512) NOT NULL,
    salt VARCHAR(512) NOT NULL,
    ...
);
```

**Risk Level:** 🟠 **HIGH**

**Impact:**
- Database breach enables offline password cracking
- With 600k PBKDF2 iterations, each guess takes ~300ms
- Attackers can use GPU clusters for massive parallel cracking
- Once master password is cracked, all stored passwords are exposed

---

### 4.5 WEAK JWT ALGORITHM (High)

**Issue:** Uses HS256 (symmetric HMAC) instead of RS256/ES256

**Evidence:**
- [`backend/utils/auth.py:94-98`](backend/utils/auth.py:94):
```python
return jwt.encode(
    payload,
    current_app.config['SECRET_KEY'],
    algorithm='HS256'  # Symmetric - same key signs and verifies!
)
```

- [`backend/utils/auth.py:121-125`](backend/utils/auth.py:121): Same issue for refresh tokens
- [`backend/utils/auth.py:142-146`](backend/utils/auth.py:142): Same issue for verification

**Comparison:**
| Algorithm | Type | Use Case |
|-----------|------|----------|
| HS256 | Symmetric (HMAC-SHA256) | Not recommended for distributed systems |
| RS256 | Asymmetric (RSA) | ✅ Recommended - private key signs, public verifies |
| ES256 | Asymmetric (ECDSA) | ✅ Recommended - more compact |

**Risk Level:** 🟠 **HIGH**

**Impact:**
- If SECRET_KEY is compromised, attacker can forge any JWT token
- No separation between signing and verification capabilities
- Harder to rotate keys in distributed systems

---

### 4.6 IN-MEDIUM SESSION BLACKLIST (Medium)

**Issue:** Token blacklist stored in memory, lost on server restart

**Evidence:**
- [`backend/utils/auth.py:18-19`](backend/utils/auth.py:18):
```python
# Token blacklist for logout (in production, use Redis)
token_blacklist: Set[str] = set()
```

**Risk Level:** 🟡 **MEDIUM**

**Impact:**
- Server restart invalidates entire blacklist
- Previously logged-out sessions become active again
- Users cannot truly "log out" if server restarts

---

### 4.7 NO HTTPS ENFORCEMENT (Medium)

**Issue:** No visible HTTPS/TLS enforcement in the implementation

**Evidence:**
- [`frontend/src/utils/api.js:7`](frontend/src/utils/api.js:7):
```javascript
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
```

- Default uses HTTP, not HTTPS
- No redirect from HTTP to HTTPS visible
- No HSTS headers configured

**Risk Level:** 🟡 **MEDIUM**

**Impact:**
- Man-in-the-Middle attacks possible
- Passwords transmitted in clear over network
- Session tokens can be intercepted

---

## 5. Comparison with Best Practices

### 5.1 OWASP Password Storage Cheat Sheet

| OWASP Recommendation | Implementation | Status |
|--------------------|----------------|--------|
| Algorithm: Argon2id preferred, PBKDF2 acceptable | PBKDF2-SHA256 | ⚠️ Acceptable |
| Memory cost: >= 64 MB | Not specified | ❌ Unknown |
| Time cost: >= 3 | 600,000 iterations | ✅ Good |
| Parallelization: 1 | Unknown | ❌ Unknown |
| Salt: >= 32 bytes | 32 bytes | ✅ Good |
| Pepper: Recommended | Not implemented | ❌ Missing |
| Iteration count reviewed yearly | Fixed at 600k | ⚠️ Static |

**Verdict:** Partial compliance, but storing password hash at all violates zero-knowledge principle.

### 5.2 NIST PQC Standards

| NIST Requirement | Implementation | Status |
|-----------------|----------------|--------|
| ML-KEM (Kyber) for key encapsulation | ML-KEM-1024 via liboqs | ✅ Compliant |
| ML-DSA (Dilithium) for signatures | ML-DSA-87 via liboqs | ✅ Compliant |
| Hybrid classical+PQC | Classical still used for auth | ⚠️ Partial |
| NIST Level 5 security | Level 5 claimed | ✅ Compliant |

**Verdict:** PQC implementation is technically correct, but unused for password authentication.

### 5.3 Zero-Knowledge Architecture Principles

| Principle | Requirement | Implementation | Status |
|-----------|-------------|----------------|--------|
| Client-side key derivation | Password never leaves client | Password sent in plain text | ❌ Violated |
| Server stores verifier only | Cannot compute password from data | Stores password hash | ❌ Violated |
| No password knowledge | Server cannot authenticate directly | Server verifies password hash | ❌ Violated |
| Forward secrecy | Compromise doesn't expose past | Not implemented | ❌ Missing |

**Verdict:** Zero-knowledge completely violated.

---

## 6. Detailed Issue Analysis

### Issue 1: Plain Text Password Transmission

| Attribute | Value |
|-----------|-------|
| **Issue ID** | SEC-001 |
| **Category** | Zero-Knowledge Violation |
| **Risk Level** | 🔴 CRITICAL |
| **File References** | [`frontend/src/utils/api.js:180-206`](frontend/src/utils/api.js:180), [`backend/routes/auth.py:55-56,175-176`](backend/routes/auth.py:55) |
| **CWE** | CWE-311: Missing Encryption of Sensitive Data |
| **OWASP** | A02:2021 Cryptographic Failures |

**Description:**
The master password is transmitted in plain text from the client to the server during registration and login. This directly contradicts the documented zero-knowledge architecture.

**Proof of Concept:**
```javascript
// frontend/src/utils/api.js:202-206
login: async (username, masterPassword) => {
  const response = await api.post('/auth/login', {
    username,
    masterPassword  // ← Plain text password in request body!
  });
}
```

**Recommended Fix:**
1. Implement SRP-6a or full SPAKE2 protocol
2. Client-side PBKDF2 before transmission
3. Send only password verifier, never password
4. Use TLS certificate pinning

---

### Issue 2: Fake PAKE (SHA256-based Verifier)

| Attribute | Value |
|-----------|-------|
| **Issue ID** | SEC-002 |
| **Category** | Weak Cryptography |
| **Risk Level** | 🔴 CRITICAL |
| **File References** | [`backend/utils/spake2_pake.py:211-249`](backend/utils/spake2_pake.py:211) |
| **CWE** | CWE-327: Use of Weak Cryptographic Algorithm |
| **OWASP** | A02:2021 Cryptographic Failures |

**Description:**
The implementation claims to use SPAKE2 but actually uses a simple SHA256(password + salt) computation. This is NOT a Password-Authenticated Key Exchange (PAKE) protocol and provides no protection against offline attacks.

**Code Evidence:**
```python
# backend/utils/spake2_pake.py:229-230
verifier_input = password.encode('utf-8') + salt
verifier = hashlib.sha256(verifier_input).digest()  # Single SHA256!
```

**Comparison with Real SPAKE2:**
- Real SPAKE2: Multiple message exchanges, elliptic curve operations
- This implementation: Single hash computation, no key exchange

**Recommended Fix:**
1. Use a proper SRP-6a implementation (e.g., `srp` Python library)
2. Or implement RFC 5054 SPAKE2 correctly
3. Ensure mathematical properties of PAKE are maintained

---

### Issue 3: Server-Side Password Hashing

| Attribute | Value |
|-----------|-------|
| **Issue ID** | SEC-003 |
| **Category** | Zero-Knowledge Violation |
| **Risk Level** | 🔴 CRITICAL |
| **File References** | [`backend/routes/auth.py:99-100`](backend/routes/auth.py:99), [`backend/utils/crypto.py:58-81`](backend/utils/crypto.py:58) |
| **CWE** | CWE-311: Missing Encryption of Sensitive Data |
| **OWASP** | A02:2021 Cryptographic Failures |

**Description:**
The server performs PBKDF2 password hashing, meaning it receives and processes the plain text master password. This completely undermines the zero-knowledge architecture claim.

**Recommended Fix:**
1. All password processing must happen client-side
2. Server should only store and verify a derived key
3. Implement OPRF (Oblivious Pseudorandom Function) for password verification

---

### Issue 4: Database Password Hash Storage

| Attribute | Value |
|-----------|-------|
| **Issue ID** | SEC-004 |
| **Category** | Data Protection |
| **Risk Level** | 🟠 HIGH |
| **File References** | [`backend/routes/auth.py:103-110`](backend/routes/auth.py:103) |
| **CWE** | CWE-916: Use of Password Hash With Insufficient Computational Effort |
| **OWASP** | A04:2021 Insecure Design |

**Description:**
Password hashes are stored in the database, enabling offline brute force attacks if the database is compromised.

**Recommended Fix:**
1. Remove password hash storage entirely
2. Use client-side only authentication
3. If verification needed, use OPRF so server cannot compute password

---

### Issue 5: Weak JWT Algorithm

| Attribute | Value |
|-----------|-------|
| **Issue ID** | SEC-005 |
| **Category** | Authentication |
| **Risk Level** | 🟠 HIGH |
| **File References** | [`backend/utils/auth.py:94-98,121-125`](backend/utils/auth.py:94) |
| **CWE** | CWE-347: Improper Verification of Cryptographic Signature |
| **OWASP** | A02:2021 Cryptographic Failures |

**Description:**
JWT tokens use HS256 (symmetric HMAC) instead of asymmetric RS256 or ES256.

**Recommended Fix:**
1. Switch to RS256 (RSA) or ES256 (ECDSA)
2. Use separate signing and verification keys
3. Implement key rotation

---

## 7. Recommendations

### Priority 1: Critical (Immediate Action Required)

| # | Recommendation | Effort | Impact |
|---|---------------|--------|--------|
| 1.1 | **Implement client-side password hashing** - Derive vault key using PBKDF2 in browser before transmission | High | Critical |
| 1.2 | **Use proper SRP-6a or full SPAKE2** - Replace fake "SPAKE2" with real PAKE protocol | High | Critical |
| 1.3 | **Stop storing password hashes** - Remove `master_password_hash` from User model | Medium | Critical |
| 1.4 | **Transmit only verifiers** - Never send plain text password over network | High | Critical |

### Priority 2: High (This Release)

| # | Recommendation | Effort | Impact |
|---|---------------|--------|--------|
| 2.1 | **Switch JWT to RS256/ES256** - Use asymmetric algorithms | Medium | High |
| 2.2 | **Implement Redis blacklist** - Persistent token revocation | Medium | High |
| 2.3 | **Enforce HTTPS** - Redirect HTTP → HTTPS, enable HSTS | Low | High |

### Priority 3: Medium (Next Release)

| # | Recommendation | Effort | Impact |
|---|---------------|--------|--------|
| 3.1 | **Implement OPRF** - Oblivious PRF for password verification | High | Medium |
| 3.2 | **Add key rotation** - Rotate PQC and JWT keys periodically | Medium | Medium |
| 3.3 | **Security headers** - Add CSP, HPKP, X-Frame-Options | Low | Medium |

### Priority 4: Long-term

| # | Recommendation | Effort | Impact |
|---|---------------|--------|--------|
| 4.1 | **Argon2id migration** - Replace PBKDF2 with Argon2id | Medium | Medium |
| 4.2 | **Hardware security** - TPM integration for key storage | High | Medium |
| 4.3 | **Audit logging** - Comprehensive security event logging | Medium | Low |

---

## 8. Conclusion

The PQC Password Manager implementation has a **fundamentally insecure architecture** that completely contradicts its documented security model. The system claims to implement a zero-knowledge architecture but actually:

1. ✅ **Transmits master password in plain text** - Complete zero-knowledge failure
2. ❌ **Uses fake "SPAKE2"** - Simple SHA256, not a real PAKE protocol  
3. ❌ **Stores password hashes on server** - Enables offline attacks
4. ✅ **Uses weak JWT algorithm** - HS256 instead of RS256/ES256
5. ✅ **Loses session blacklist on restart** - In-memory storage

**The system cannot be considered secure for storing sensitive passwords until these critical issues are addressed.**

The PQC (post-quantum cryptography) implementation itself is technically correct and uses proper NIST-standard algorithms (ML-KEM-1024, ML-DSA-87), but this strength is undermined by the fundamental authentication flaws.

---

## Appendix A: File Reference Index

| File | Purpose | Security-Relevant Lines |
|------|---------|------------------------|
| `frontend/src/utils/api.js` | API client | 180-206 (plain text password) |
| `frontend/src/components/Register.js` | Registration UI | 99 (password sent to server) |
| `frontend/src/components/Login.js` | Login UI | 76 (password sent to server) |
| `backend/routes/auth.py` | Auth endpoints | 55-56, 99-100, 175-176 (password handling) |
| `backend/utils/spake2_pake.py` | PAKE implementation | 211-249 (fake SPAKE2) |
| `backend/utils/crypto.py` | Crypto utilities | 58-81 (server-side hashing) |
| `backend/utils/auth.py` | JWT handling | 94-98 (HS256 algorithm) |

---

## Appendix B: Testing Recommendations

1. **Network Sniffing Test**: Capture traffic during registration/login to verify plain text transmission
2. **Database Inspection**: Verify password hash storage in users table
3. **Code Review**: Trace password flow from client input to server storage
4. **Penetration Test**: Attempt offline password cracking with hashcat

---

*Document generated as part of security assessment. Classification: Internal Use Only.*
