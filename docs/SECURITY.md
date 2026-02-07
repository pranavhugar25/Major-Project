# Security Guide

## Zero-Knowledge Architecture

### What is Zero-Knowledge?

A zero-knowledge system means the server **never** has access to your unencrypted data. In our implementation:

- Your master password never leaves your device in plain text
- The vault key is derived locally using your master password + salt
- All encryption/decryption happens in your browser
- The server only sees encrypted ciphertext

### How It Works

1. **Key Derivation (Client-Side Only)**
   ```
   Vault Key = PBKDF2(MasterPassword + Salt, 600,000 iterations)
   ```

2. **Encryption (Client-Side)**
   ```
   Encrypted = AES-256-GCM(Password, Vault Key, IV)
   ```

3. **Storage (Server-Side)**
   ```
   Database stores: {encrypted_data, iv, auth_tag}
   Server cannot decrypt without Vault Key
   ```

4. **Decryption (Client-Side)**
   ```
   Password = AES-256-GCM-Decrypt(Encrypted, Vault Key, IV)
   ```

## Post-Quantum Cryptography

### Why PQC Matters

Quantum computers threaten current encryption:
- **Shor's Algorithm** can break RSA and ECC
- **"Harvest Now, Decrypt Later"** attacks capture encrypted data today for future decryption
- PQC algorithms are resistant to quantum attacks

### Our PQC Implementation

#### ML-KEM (Kyber)
- **Purpose:** Key encapsulation for session keys
- **Security Level:** NIST Level 5 (256-bit quantum security)
- **Key Sizes:** 
  - Public: 1568 bytes
  - Private: 3168 bytes
- **Use Case:** Secure communication channel

#### ML-DSA (Dilithium)
- **Purpose:** Digital signatures for authentication
- **Security Level:** NIST Level 5
- **Key Sizes:**
  - Public: 2592 bytes
  - Private: 4864 bytes
- **Use Case:** Server identity verification

### PQC Session Flow

```
1. Client ←→ Server: Initiate PQC handshake
2. Server generates Kyber + Dilithium keys
3. Client encapsulates session key with Server's Kyber public key
4. Server decapsulates session key
5. All subsequent communication encrypted with session key
6. Server signs responses with Dilithium private key
7. Client verifies signatures with Dilithium public key
```

## Cryptographic Primitives

### PBKDF2 Key Derivation
- **Hash Function:** HMAC-SHA256
- **Iterations:** 600,000 (OWASP 2024 recommendation)
- **Output:** 256-bit key
- **Salt:** 256-bit random, unique per user

**Why 600,000 iterations?**
- Balances security vs. performance
- Makes brute force attacks computationally expensive
- ~300-500ms on modern hardware (acceptable UX)

### AES-256-GCM
- **Mode:** Galois/Counter Mode
- **Key Size:** 256 bits
- **IV Size:** 96 bits (recommended for GCM)
- **Authentication Tag:** 128 bits
- **Benefits:**
  - Authenticated encryption (integrity + confidentiality)
  - Parallelizable (fast)
  - NIST approved

### Salt Generation
```python
import secrets
salt = secrets.token_bytes(32)  # 256 bits
```
- Cryptographically secure random
- Unique per user
- Stored in database
- Used for PBKDF2 key derivation

### IV Generation
```python
import secrets
iv = secrets.token_bytes(12)  # 96 bits for GCM
```
- Cryptographically secure random
- Unique per encryption operation
- Never reused with same key
- Stored with ciphertext

## Best Practices

### For Users

1. **Choose a Strong Master Password**
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, symbols
   - Avoid dictionary words
   - Consider a passphrase: "correct horse battery staple"

2. **Never Share Your Master Password**
   - Not even with support staff
   - We can't recover it if lost

3. **Use Unique Passwords Per Site**
   - Use the password generator
   - Never reuse passwords

4. **Keep Software Updated**
   - Browser updates include security patches
   - Update the application regularly

5. **Secure Your Device**
   - Use full-disk encryption
   - Lock when unattended
   - Install antivirus/antimalware

### For Developers

1. **Never Log Sensitive Data**
   ```python
   # BAD
   print(f"Password: {password}")
   
   # GOOD
   print("Password received")
   ```

2. **Use Constant-Time Comparisons**
   ```python
   import secrets
   secrets.compare_digest(hash1, hash2)  # Prevents timing attacks
   ```

3. **Validate All Inputs**
   ```python
   if not username or len(username) > 255:
       raise ValueError("Invalid username")
   ```

4. **Use Prepared Statements**
   ```python
   # SQLAlchemy ORM handles this automatically
   user = User.query.filter_by(username=username).first()
   ```

5. **Implement Rate Limiting**
   ```python
   from flask_limiter import Limiter
   limiter = Limiter(app, default_limits=["200 per day", "50 per hour"])
   ```

## Security Checklist

### Development
- [ ] No hardcoded secrets
- [ ] Environment variables for config
- [ ] Input validation on all endpoints
- [ ] Error messages don't leak info
- [ ] HTTPS enabled
- [ ] CORS properly configured
- [ ] SQL injection prevention
- [ ] XSS prevention
- [ ] CSRF protection

### Production (Additional)
- [ ] Change default secret key
- [ ] Use PostgreSQL instead of SQLite
- [ ] Enable database encryption at rest
- [ ] Set up regular backups
- [ ] Implement rate limiting
- [ ] Add monitoring and alerting
- [ ] Use a reverse proxy (nginx)
- [ ] Enable security headers
- [ ] Implement account lockout
- [ ] Add audit logging
- [ ] Use a CDN for frontend
- [ ] Enable 2FA
- [ ] Regular security audits
- [ ] Penetration testing

## Common Vulnerabilities & Mitigations

### 1. SQL Injection
**Risk:** Attacker injects malicious SQL
**Mitigation:** Use SQLAlchemy ORM with parameterized queries

### 2. XSS (Cross-Site Scripting)
**Risk:** Attacker injects malicious JavaScript
**Mitigation:** React auto-escapes content, CSP headers

### 3. CSRF (Cross-Site Request Forgery)
**Risk:** Attacker tricks user into making unwanted requests
**Mitigation:** CSRF tokens, SameSite cookies

### 4. Man-in-the-Middle
**Risk:** Attacker intercepts communication
**Mitigation:** HTTPS/TLS + PQC encryption

### 5. Brute Force
**Risk:** Attacker tries many passwords
**Mitigation:** PBKDF2 iterations + rate limiting + account lockout

### 6. Timing Attacks
**Risk:** Attacker measures response times to leak info
**Mitigation:** Constant-time comparisons (secrets.compare_digest)

### 7. Rainbow Tables
**Risk:** Precomputed password hashes
**Mitigation:** Unique salts per user

### 8. Session Hijacking
**Risk:** Attacker steals session token
**Mitigation:** Secure cookies, short expiration, HTTPS only

## Incident Response

If you suspect a security breach:

1. **Immediately:**
   - Change your master password
   - Lock your vault
   - Sign out all sessions

2. **Investigate:**
   - Check recent activity
   - Review access logs
   - Identify compromised accounts

3. **Remediate:**
   - Delete suspicious entries
   - Update all stored passwords
   - Enable additional security

4. **Report:**
   - Contact security team
   - Document timeline
   - Preserve evidence

## Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Web Security Academy](https://portswigger.net/web-security)
- [PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)

## Responsible Disclosure

Found a security vulnerability?

1. **Do NOT** publicly disclose
2. Email: security@example.com
3. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (optional)

We commit to:
- Acknowledge within 48 hours
- Investigate promptly
- Keep you updated
- Credit you (if desired)
