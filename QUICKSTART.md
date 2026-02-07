# Quick Start Guide

## 🚀 Get Started in 5 Minutes

### Prerequisites
- Python 3.10 or higher
- Node.js 18 or higher
- npm (comes with Node.js)

### Option 1: Automated Setup (Recommended)

#### Linux/Mac:
```bash
chmod +x setup.sh
./setup.sh
```

#### Windows:
```cmd
setup.bat
```

### Option 2: Manual Setup

#### Backend Setup
```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# Linux/Mac:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python app.py
```

The backend will start on `http://localhost:5000`

#### Frontend Setup (New Terminal)
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm start
```

The frontend will start on `http://localhost:3000`

## 🎯 First Steps

1. **Open your browser** to `http://localhost:3000`

2. **Create your vault:**
   - Click "Create New Vault"
   - Choose a username
   - Create a strong master password
   - Remember: This password cannot be recovered!

3. **Add your first password:**
   - Click "Add Password" in the sidebar
   - Enter website URL (e.g., "google.com")
   - Enter your username for that site
   - Either enter a password or click "Generate Strong Password"
   - Click "Save Password"

4. **View your passwords:**
   - Click "Stored Passwords" in the sidebar
   - Click "Show" to decrypt and view a password
   - Click "Copy" to copy to clipboard
   - Click "Hide" to re-encrypt

5. **See the encryption in action:**
   - Click "Crypto View" in the sidebar
   - See the raw encrypted data the server stores
   - Verify zero-knowledge architecture

## 🔐 Key Features to Try

### Password Generator
- In "Add Password", click "🎲 Generate Strong Password"
- Creates cryptographically secure passwords
- Includes uppercase, lowercase, numbers, and symbols

### Zero-Knowledge Verification
- Go to "Crypto View"
- See that server only stores encrypted ciphertext
- Verify your passwords are never visible to the server

### Vault Locking
- Click "🔒 Lock Vault" to lock without signing out
- Vault key is removed from memory
- Must re-enter master password to unlock

## 📱 Browser Support

Tested on:
- ✅ Chrome 90+
- ✅ Firefox 88+
- ✅ Safari 14+
- ✅ Edge 90+

## 🔧 Troubleshooting

### Backend won't start
```bash
# Make sure you're in the virtual environment
# You should see (venv) in your terminal prompt

# If not, activate it:
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows

# Try installing dependencies again
pip install -r requirements.txt
```

### Frontend won't start
```bash
# Clear npm cache
npm cache clean --force

# Delete node_modules and reinstall
rm -rf node_modules
npm install
```

### CORS errors
- Make sure backend is running on port 5000
- Make sure frontend is running on port 3000
- Check backend console for CORS configuration

### Can't connect to backend
- Verify backend is running: visit `http://localhost:5000`
- Should see JSON response with API info
- Check firewall settings

## 💡 Tips

1. **Use a strong master password**: This is your only key to your vault
2. **Generate unique passwords**: Use the built-in generator for each site
3. **Lock when done**: Click "Lock Vault" when stepping away
4. **Try the Crypto View**: Understand how zero-knowledge works

## 📚 Next Steps

- Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) to understand the system
- Review [SECURITY.md](docs/SECURITY.md) for security best practices
- Check [API.md](docs/API.md) for API documentation
- Explore the code to learn about PQC implementation

## 🐛 Found a Bug?

- Check existing issues
- Create detailed bug report
- Include steps to reproduce
- Share relevant logs

## 🎓 Learning Resources

- **Zero-Knowledge Architecture**: docs/ARCHITECTURE.md
- **Post-Quantum Crypto**: docs/SECURITY.md
- **API Reference**: docs/API.md
- **Code Examples**: Browse source code with comments

Enjoy your quantum-resistant password manager! 🔒🚀
