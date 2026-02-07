# System Architecture

## Overview

The PQC Password Manager implements a **Zero-Knowledge Architecture** with **Post-Quantum Cryptography** to secure user passwords against both current and future threats.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Client (Browser)                     │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  React Frontend                                        │ │
│  │  • User Interface                                      │ │
│  │  • Client-side Crypto (AES-256, PBKDF2)               │ │
│  │  • PQC Key Exchange (ML-KEM, ML-DSA)                  │ │
│  └────────────────────────────────────────────────────────┘ │
│                           ↕ HTTPS + PQC                      │
└─────────────────────────────────────────────────────────────┘
                              │
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      Backend Server                          │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Flask API                                             │ │
│  │  • Authentication endpoints                            │ │
│  │  • Password CRUD operations                            │ │
│  │  • Zero-knowledge data handling                        │ │
│  └────────────────────────────────────────────────────────┘ │
│                           ↕                                  │
│  ┌────────────────────────────────────────────────────────┐ │
│  │  Database (SQLite/PostgreSQL)                          │ │
│  │  • Users (hashed passwords, salts)                     │ │
│  │  • Encrypted password entries                          │ │
│  │  • PQC session keys                                    │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Zero-Knowledge Flow

### 1. User Registration

```
User                    Client                    Server
  │                       │                         │
  │ Enter credentials     │                         │
  ├──────────────────────>│                         │
  │                       │                         │
  │                       │ Generate salt           │
  │                       │ Derive vault key (PBKDF2)
  │                       │ Hash master password    │
  │                       │                         │
  │                       │ POST /auth/register     │
  │                       │ {username, hash}        │
  │                       ├────────────────────────>│
  │                       │                         │
  │                       │                         │ Store user
  │                       │                         │ Store salt
  │                       │                         │ Store hash
  │                       │                         │
  │                       │ ← {userId, salt}        │
  │                       │<────────────────────────┤
  │                       │                         │
  │                       │ Keep vault key in RAM   │
  │ Login success         │                         │
  │<──────────────────────┤                         │
```

### 2. Password Storage

```
User                    Client                    Server
  │                       │                         │
  │ Save new password     │                         │
  ├──────────────────────>│                         │
  │                       │                         │
  │                       │ Encrypt with vault key  │
  │                       │ (AES-256-GCM)          │
  │                       │                         │
  │                       │ POST /passwords/add     │
  │                       │ {encrypted, iv, tag}    │
  │                       ├────────────────────────>│
  │                       │                         │
  │                       │                         │ Store encrypted
  │                       │ ← {success}             │ data only
  │                       │<────────────────────────┤
  │ Success confirmation  │                         │
  │<──────────────────────┤                         │
```

### 3. Password Retrieval

```
User                    Client                    Server
  │                       │                         │
  │ View password         │                         │
  ├──────────────────────>│                         │
  │                       │                         │
  │                       │ GET /passwords/get-all  │
  │                       ├────────────────────────>│
  │                       │                         │
  │                       │                         │ Fetch encrypted
  │                       │ ← {encrypted data}      │ data
  │                       │<────────────────────────┤
  │                       │                         │
  │                       │ Decrypt with vault key  │
  │                       │ (AES-256-GCM)          │
  │                       │                         │
  │ Show plain password   │                         │
  │<──────────────────────┤                         │
```

## Security Layers

### Layer 1: Client-Side Encryption
- **Algorithm:** AES-256-GCM
- **Key Derivation:** PBKDF2-HMAC-SHA256 (600k iterations)
- **IV:** Random 96-bit per encryption
- **Auth Tag:** 128-bit for integrity verification

### Layer 2: Post-Quantum Protection
- **ML-KEM (Kyber):** 
  - Key encapsulation mechanism
  - Security level: NIST Level 5
  - Protects session keys from quantum attacks
  
- **ML-DSA (Dilithium):**
  - Digital signature algorithm
  - Security level: NIST Level 5
  - Ensures server authenticity

### Layer 3: Transport Security
- **HTTPS/TLS 1.3** for encrypted communication
- **PQC Hybrid Mode** for quantum-resistant tunneling
- **Certificate Pinning** (production recommendation)

### Layer 4: Server-Side Protection
- **Password Hashing:** PBKDF2-SHA256 (600k iterations)
- **Unique Salts:** 256-bit random per user
- **No Plain Text Storage:** Master passwords never stored
- **Database Encryption:** Encrypted at rest (production)

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    user_id UUID UNIQUE NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    master_password_hash VARCHAR(512) NOT NULL,
    salt VARCHAR(512) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### Passwords Table
```sql
CREATE TABLE passwords (
    id INTEGER PRIMARY KEY,
    password_id UUID UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    site_url VARCHAR(512) NOT NULL,
    site_username VARCHAR(255) NOT NULL,
    encrypted_password TEXT NOT NULL,
    iv VARCHAR(512) NOT NULL,
    auth_tag VARCHAR(512),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, site_url)
);
```

### PQC Sessions Table
```sql
CREATE TABLE pqc_sessions (
    id INTEGER PRIMARY KEY,
    session_id UUID UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    kyber_public_key TEXT NOT NULL,
    dilithium_public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);
```

## Technology Stack

### Frontend
- **Framework:** React 18.2
- **HTTP Client:** Axios
- **Crypto Library:** CryptoJS
- **Styling:** Custom CSS with CSS Variables
- **Fonts:** Google Fonts (Outfit, Space Mono)

### Backend
- **Framework:** Flask 3.0
- **ORM:** SQLAlchemy 2.0
- **Database:** SQLite (dev), PostgreSQL (production)
- **Crypto:** cryptography, pycryptodome
- **PQC:** kyber-py, dilithium-py (simulated)

## Threat Model

### Protected Against:
✅ Man-in-the-Middle attacks (HTTPS + PQC)
✅ Server breaches (Zero-Knowledge)
✅ Database leaks (Encrypted data)
✅ Quantum computer attacks (PQC)
✅ Rainbow table attacks (Unique salts)
✅ Brute force (PBKDF2 iterations)

### Not Protected Against:
⚠️ Client-side malware/keyloggers
⚠️ Phishing attacks
⚠️ User choosing weak master password
⚠️ Social engineering
⚠️ Physical device theft (without encryption)

## Future Enhancements

1. **Browser Extension**
   - Auto-fill credentials
   - Site detection
   - Form injection

2. **Multi-Device Sync**
   - End-to-end encrypted sync
   - Device authentication
   - Conflict resolution

3. **Advanced Features**
   - Password sharing (encrypted)
   - Two-factor authentication
   - Biometric unlock
   - Password strength analysis
   - Breach monitoring

4. **Enterprise Features**
   - Team vaults
   - Role-based access
   - Audit logs
   - Compliance reporting
