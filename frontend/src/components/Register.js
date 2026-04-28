/**
 * Register Component
 * Handles new user registration with zero-knowledge architecture
 * Integrates PQC (Post-Quantum Cryptography) for enhanced security
 */
import React, { useState } from 'react';
import { authAPI } from '../utils/api';
import { calculatePasswordStrength } from '../utils/crypto';
import { setAuthTokens } from '../utils/api';
import { 
  initPQC,
  isPQCAvailable,
  generateKeypair, 
  encapsulate,
  initSession,
  getMLDSA,
  verify
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
        // Check if noble-post-quantum is already loaded
        if (isPQCAvailable()) {
          setPqcStatus('ready');
          console.log('[Register] PQC initialized successfully (noble-post-quantum)');
          return;
        }
        
        // Initialize PQC
        const status = await initPQC();
        if (status.available) {
          setPqcStatus('ready');
        } else {
          throw new Error(status.error || 'PQC not available');
        }
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
      // Generate PQC keypair (ML-KEM-1024) for session
      console.log('[Register] Generating ML-KEM-1024 keypair...');
      const clientKeypair = await generateKeypair();
      console.log('[Register] Keypair generated');

      // Register user (no PQC key sent; we use ephemeral key per session)
      const response = await authAPI.register(username, masterPassword);
      console.log('[Register] User registered');

      if (response.success) {
        // Store JWT tokens
        setAuthTokens({
          access_token: response.access_token,
          refresh_token: response.refresh_token,
          expires_in: response.expires_in
        });

        // Initialize PQC session and derive vault key using ML-KEM
        try {
          setPqcStatus('connecting');
          console.log('[Register] Initializing PQC session...');

          // Get server's PQC session data
          const session = await initSession(username, response.userId);
          console.log('[Register] Session received:', session.session_id.substring(0, 16) + '...');

            // Verify server ML-DSA-87 signature (optional but recommended)
            if (session.server_signing_key && session.session_signature) {
              console.log('[Register] Verifying server ML-DSA-87 signature...');
              
              // Decode base64 signature and session_id
              const sessionIdBytes = new TextEncoder().encode(session.session_id);
              const signatureBytes = Uint8Array.from(atob(session.session_signature), c => c.charCodeAt(0));
              const serverSigningKey = Uint8Array.from(atob(session.server_signing_key), c => c.charCodeAt(0));

              const isValid = await verify(
                signatureBytes,
                sessionIdBytes,
                serverSigningKey
              );
              if (isValid) {
                console.log('[Register] ✓ Server signature verified (ML-DSA-87)');
              } else {
                throw new Error('ML-DSA-87 signature verification failed');
              }
            } else {
              console.warn('[Register] No server signature - skipping verification');
            }

           // Perform key encapsulation
           console.log('[Register] Encapsulating shared secret...');
           const serverPublicKeyUint8 = Uint8Array.from(atob(session.server_public_key), c => c.charCodeAt(0));
           const encapsulation = await encapsulate(serverPublicKeyUint8);
           const vaultKeyUint8 = encapsulation.sharedSecret;
           const vaultKey = btoa(String.fromCharCode(...vaultKeyUint8));
           console.log('[Register] ✓ Vault key derived using ML-KEM-1024');

          // Send client public key to server
          console.log('[Register] Sending client public key to server...');
          await authAPI.confirmPQCSession(session.session_id, {
            client_public_key: Array.from(clientKeypair.publicKey)
          });

          setPqcStatus('connected');
          console.log('[Register] ✓ PQC session established');

          onRegisterSuccess({
            userId: response.userId,
            username: response.username,
            salt: response.salt
          }, vaultKey);

        } catch (pqcErr) {
          console.error('[Register] PQC setup failed:', pqcErr);
          setPqcStatus('error');
          setPqcError('PQC session failed: ' + pqcErr.message);
          setError('Failed to establish quantum-resistant session. Please try again.');
          setLoading(false);
        }

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
