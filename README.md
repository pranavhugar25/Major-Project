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

## ⚙️ Environment Configuration

Create a `.env` file in the project root (or modify the existing one) with the following variables:

### Backend Variables (Flask)

| Variable | Description | Default |
|----------|-------------|----------|
| `FLASK_APP` | Flask application entry point | `app.py` |
| `FLASK_ENV` | Environment mode | `development` |
| `FLASK_DEBUG` | Enable debug mode | `false` |
| `SECRET_KEY` | Secret key for JWT/sessions (change in production!) | `dev-secret-key-change-in-production` |
| `DATABASE_URL` | Database connection string | `sqlite:///pqc_password_manager.db` |
| `RATELIMIT_STORAGE_URL` | Rate limiting storage | `memory://` |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:3000 http://127.0.0.1:3000` |

### Frontend Variables

| Variable | Description | Default |
|----------|-------------|----------|
| `REACT_APP_API_URL` | Backend API URL | `http://localhost:5000/api` |

### Example `.env` File

```env
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
FLASK_DEBUG=false

# Security - Generate a secure secret key for production use
SECRET_KEY=your-secure-random-secret-key-here

# Database (SQLite default - suitable for development)
DATABASE_URL=sqlite:///pqc_password_manager.db

# Rate Limiting (memory default for development)
RATELIMIT_STORAGE_URL=memory://

# CORS Origins (localhost for development)
CORS_ORIGINS=http://localhost:3000 http://127.0.0.1:3000

# Frontend API URL
REACT_APP_API_URL=http://localhost:5000/api
```

### Production Considerations

- **SECRET_KEY**: Generate a strong random key (e.g., using `python -c "import secrets; print(secrets.token_hex(32))")`)
- **DATABASE_URL**: Consider PostgreSQL for production
- **CORS_ORIGINS**: Restrict to your actual domain
- **FLASK_DEBUG**: Set to `false` in production

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
