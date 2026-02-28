# Zero-Knowledge Post-Quantum Cryptography Password Manager

A secure, web-based password management system designed to protect user credentials against both present-day cyber threats and future quantum computing attacks.

## 🔒 Key Features

- **Zero-Knowledge Architecture**: All encryption/decryption happens client-side
- **Post-Quantum Cryptography**: ML-KEM (Kyber) and ML-DSA (Dilithium) protection
- **AES-256-GCM Encryption**: Industry-standard authenticated encryption
- **PBKDF2 Key Derivation**: Secure vault key generation
- **Transparent Crypto View**: See encrypted data to verify zero-knowledge claims

## 🏗️ Architecture

### Frontend (React + TypeScript)
- Client-side encryption/decryption
- PQC secure communication
- Modern, secure UI

### Backend (Python Flask)
- SQLAlchemy database management
- Zero-knowledge data storage
- RESTful API endpoints

## 🚀 Quick Start

This project uses a hybrid setup: **backend runs in Docker**, **frontend runs with npm**.

### Prerequisites
- Node.js 18+ and npm
- Docker and Docker Compose

### Backend Setup (Docker)

```bash
# Start the backend using Docker Compose
docker-compose up --build -d
```

The backend will run on `http://localhost:5000`

### Frontend Setup (npm)

```bash
cd frontend
npm install
npm start
```

The frontend will run on `http://localhost:3000`

## 📁 Project Structure

```
pqc-password-manager/
├── frontend/
│   ├── src/
│   │   ├── components/     # React components
│   │   ├── utils/          # Crypto utilities
│   │   └── styles/         # CSS styles
│   └── public/             # Static assets
├── backend/
│   ├── models/             # Database models
│   ├── routes/             # API routes
│   ├── utils/              # Crypto utilities
│   └── app.py              # Flask application
└── docs/                   # Documentation
```

## 🔐 Security Features

### Zero-Knowledge Model
- Master password never sent to server
- Vault key derived client-side only
- All credentials encrypted before transmission

### Post-Quantum Protection
- **ML-KEM (Kyber)**: Secure key encapsulation
- **ML-DSA (Dilithium)**: Digital signatures
- Protection against "harvest now, decrypt later" attacks

### Encryption Stack
- AES-256-GCM for data encryption
- PBKDF2 with unique salts per user
- Authenticated encryption with integrity checks

## 🎯 Usage

1. **Register**: Create account with username and master password
2. **Login**: Authenticate and derive vault key locally
3. **Add Password**: Store credentials for any website
4. **View Passwords**: Decrypt and view stored credentials
5. **Crypto View**: Inspect encrypted data to verify security

## 🔮 Future Enhancements

- Browser extension integration
- Auto-fill functionality
- Password strength analyzer
- Import/export encrypted vaults
- Multi-device sync with end-to-end encryption

## ⚠️ Security Notice

This is a demonstration project. For production use:
- Implement rate limiting
- Add HTTPS/TLS
- Enable CORS properly
- Add session management
- Implement account recovery
- Add audit logging

## 📄 License

MIT License - See LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📧 Contact

For questions or issues, please open a GitHub issue.
