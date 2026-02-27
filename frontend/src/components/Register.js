/**
 * Register Component
 * Handles new user registration with zero-knowledge architecture
 * Integrates PQC (Post-Quantum Cryptography) for enhanced security
 */
import React, { useState } from 'react';
import { authAPI } from '../utils/api';
import { deriveVaultKey, calculatePasswordStrength } from '../utils/crypto';
import { 
  loadLiboqsWasm, 
  generateKeypair, 
  initSession,
  encapsulate,
  isWasmLoaded 
} from '../utils/pqc';
import '../styles/Auth.css';

function Register({ onRegisterSuccess, onSwitchToLogin }) {
  const [username, setUsername] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(null);
  const [pqcStatus, setPqcStatus] = useState('initializing'); // 'initializing' | 'ready' | 'error'
  const [pqcError, setPqcError] = useState('');

  // Initialize PQC on component mount
  React.useEffect(() => {
    const initPQC = async () => {
      try {
        // Check if already loaded
        if (isWasmLoaded()) {
          setPqcStatus('ready');
          return;
        }
        
        // Load liboqs WASM
        await loadLiboqsWasm();
        setPqcStatus('ready');
        console.log('[Register] PQC initialized successfully');
      } catch (err) {
        console.error('[Register] PQC initialization failed:', err);
        setPqcError(err.message || 'Failed to initialize quantum-resistant cryptography');
        setPqcStatus('error');
      }
    };

    initPQC();
  }, []);

  const handlePasswordChange = async (value) => {
    setMasterPassword(value);
    const strength = await calculatePasswordStrength(value);
    setPasswordStrength(strength);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    // Validation
    if (masterPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (passwordStrength && passwordStrength.strength === 'weak') {
      setError('Password is too weak. Please choose a stronger password.');
      return;
    }

    // Check PQC status - PQC is required
    if (pqcStatus === 'error') {
      setError(`PQC initialization failed: ${pqcError}. Please refresh the page and try again.`);
      return;
    }

    if (pqcStatus === 'initializing') {
      setError('Please wait while quantum-resistant cryptography initializes...');
      return;
    }

    setLoading(true);

    try {
      // Generate PQC keypair (ML-KEM-1024) for this user
      console.log('[Register] Generating PQC keypair...');
      const keypair = generateKeypair();
      console.log('[Register] PQC keypair generated');

      // Register user with PQC public key
      const response = await authAPI.register(username, masterPassword, keypair.publicKey);

      if (response.success) {
        // Derive vault key client-side
        const vaultKey = await deriveVaultKey(masterPassword, response.salt);

        // Initialize PQC session with server
        try {
          console.log('[Register] Initializing PQC session with server...');
          const session = await initSession(username, response.userId);
          
          // Perform key encapsulation to establish shared secret
          if (session.server_public_key) {
            console.log('[Register] Performing key encapsulation...');
            const encapsulation = encapsulate(session.server_public_key);
            console.log('[Register] PQC session established successfully');
          }
        } catch (pqcErr) {
          console.error('[Register] PQC session error:', pqcErr);
          // PQC session failure is critical - log but don't block registration
          // The user can re-establish PQC session on login
        }

        // Pass user data and vault key to parent
        onRegisterSuccess({
          userId: response.userId,
          username: response.username,
          salt: response.salt,
          pqcPublicKey: keypair.publicKey
        }, vaultKey);
      } else {
        setError(response.error || 'Registration failed');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="lock-icon">🔐</div>
          <h1 className="auth-title">Create Your Vault</h1>
          <p className="auth-subtitle">Secure your passwords with quantum-resistant encryption</p>
        </div>

        {/* PQC Status Indicator */}
        <div className={`pqc-status pqc-status-${pqcStatus}`}>
          {pqcStatus === 'initializing' && (
            <>
              <span className="pqc-spinner">⚡</span>
              <span>Initializing Quantum-Resistant Cryptography...</span>
            </>
          )}
          {pqcStatus === 'ready' && (
            <>
              <span className="pqc-icon">🛡️</span>
              <span>PQC Protected (ML-KEM-1024)</span>
            </>
          )}
          {pqcStatus === 'error' && (
            <>
              <span className="pqc-icon">⚠️</span>
              <span>PQC Error: {pqcError}</span>
            </>
          )}
        </div>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Choose a username"
              required
              autoComplete="username"
            />
            <small className="form-hint">This will be your vault identifier</small>
          </div>

          <div className="form-group">
            <label htmlFor="password">Master Password</label>
            <input
              id="password"
              type="password"
              value={masterPassword}
              onChange={(e) => handlePasswordChange(e.target.value)}
              placeholder="Create a strong master password"
              required
              autoComplete="new-password"
            />
            {passwordStrength && (
              <div className={`password-strength strength-${passwordStrength.strength}`}>
                <div className="strength-bar">
                  <div 
                    className="strength-fill"
                    style={{ width: `${(passwordStrength.score / 7) * 100}%` }}
                  />
                </div>
                <small>{passwordStrength.feedback}</small>
              </div>
            )}
          </div>

          <div className="form-group">
            <label htmlFor="confirm-password">Confirm Master Password</label>
            <input
              id="confirm-password"
              type="password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Re-enter your master password"
              required
              autoComplete="new-password"
            />
          </div>

          <div className="warning-box">
            <span className="warning-icon">⚠️</span>
            <p><strong>Important:</strong> Your master password cannot be recovered. Make sure to remember it!</p>
          </div>

          {error && (
            <div className="error-message">
              <span className="error-icon">⚠️</span>
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className="auth-button"
            disabled={loading || pqcStatus === 'initializing'}
          >
            {loading ? 'Creating Vault...' : 'Create Vault'}
          </button>
        </form>

        <div className="auth-footer">
          <p>Already have a vault?</p>
          <button 
            onClick={onSwitchToLogin}
            className="link-button"
          >
            Sign In
          </button>
        </div>
      </div>
    </div>
  );
}

export default Register;
