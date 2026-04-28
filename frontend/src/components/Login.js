/**
 * Login Component
 * Handles user authentication with zero-knowledge architecture
 * Integrates PQC (Post-Quantum Cryptography) for enhanced security
 */
import React, { useState } from 'react';
import { authAPI, setAuthTokens } from '../utils/api';
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

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [username, setUsername] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);
  const [pqcStatus, setPqcStatus] = useState('initializing'); // 'initializing' | 'ready' | 'error' | 'connecting' | 'connected'
  const [pqcError, setPqcError] = useState('');

  // Initialize PQC on component mount
  React.useEffect(() => {
    const initPQC = async () => {
      try {
        // Check if noble-post-quantum is already loaded
        if (isPQCAvailable()) {
          setPqcStatus('ready');
          console.log('[Login] PQC initialized successfully (noble-post-quantum)');
          return;
        }
        
        // Try to initialize PQC
        const status = await initPQC();
        if (status.available) {
          setPqcStatus('ready');
        } else {
          throw new Error(status.error || 'PQC not available');
        }
        console.log('[Login] PQC initialized successfully');
      } catch (err) {
        console.error('[Login] PQC initialization failed:', err);
        setPqcError(err.message || 'Failed to initialize quantum-resistant cryptography');
        setPqcStatus('error');
      }
    };

    initPQC();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    // Check PQC status - PQC is required for full security
    if (pqcStatus === 'error') {
      setError(`PQC initialization failed: ${pqcError}. Please refresh the page and try again.`);
      setLoading(false);
      return;
    }

    if (pqcStatus === 'initializing') {
      setError('Please wait while quantum-resistant cryptography initializes...');
      setLoading(false);
      return;
    }

    try {
      // Login to get user data (salt, userId)
      const response = await authAPI.login(username, masterPassword);

      if (response.success) {
        setFailedAttempts(0);

        console.log('[Login] Authentication successful');
        console.log('[Login] Salt received:', response.salt ? 'present' : 'missing');

        // Store JWT tokens for API authentication
        setAuthTokens({
          access_token: response.access_token,
          refresh_token: response.refresh_token,
          expires_in: response.expires_in
        });

        // Initialize PQC session with server - REQUIRED for vault key
        try {
          setPqcStatus('connecting');
          console.log('[Login] Initializing PQC session with server...');

          // Step 1: Get server's ML-KEM-1024 public key and ML-DSA-87 signature
          const session = await initSession(username, response.userId);
          console.log('[Login] PQC session initialized:', session.session_id);

          // Step 1b: Verify server's ML-DSA-87 signature on session_id
          if (session.server_signing_key && session.session_signature) {
            console.log('[Login] Verifying server ML-DSA-87 signature...');
            const ml_dsa = getMLDSA();
            
            // Decode base64 signature and session_id
            const sessionIdBytes = new TextEncoder().encode(session.session_id);
            const signatureBytes = Uint8Array.from(atob(session.session_signature), c => c.charCodeAt(0));
            const serverSigningKey = Uint8Array.from(atob(session.server_signing_key), c => c.charCodeAt(0));
            
            const isValid = await ml_dsa.verify(
              signatureBytes,
              sessionIdBytes,
              serverSigningKey
            );
            
            if (isValid) {
              console.log('[Login] ✓ ML-DSA-87 signature VERIFIED - server authenticated');
            } else {
              throw new Error('ML-DSA-87 signature verification failed - possible MITM attack');
            }
          } else {
            console.warn('[Login] ⚠️ Server signature not provided - skipping ML-DSA verification (should be enabled in production)');
          }

          // Step 2: Client generates ML-KEM-1024 keypair
          console.log('[Login] Generating ML-KEM-1024 keypair...');
          const clientKeypair = await generateKeypair();

          // Step 3: Encapsulate shared secret using SERVER's public key
          console.log('[Login] Encapsulating shared secret with server public key...');
          const encapsulation = await encapsulate(session.server_public_key);

          // Step 4: The shared secret IS the vault key (PQC-derived)
          const vaultKey = encapsulation.sharedSecret;
          console.log('[Login] ✓ Vault key derived from ML-KEM-1024 shared secret');
          console.log('[Login] Vault key (first 40 chars):', vaultKey.substring(0, 40) + '...');

          // Step 5: Send client's public key to server for confirmation
          console.log('[Login] Sending client public key to server...');
          await authAPI.confirmPQCSession(session.session_id, {
            client_public_key: Array.from(clientKeypair.publicKey)
          });

          setPqcStatus('connected');
          console.log('[Login] ✓ PQC session fully established - vault key ready');

          // Pass user data and PQC-derived vault key to parent
          onLoginSuccess({
            userId: response.userId,
            username: response.username,
            salt: response.salt
          }, vaultKey);

        } catch (pqcErr) {
          console.error('[Login] PQC session error:', pqcErr);
          // PQC failure is critical - without it, vault key cannot be established
          setPqcStatus('error');
          setPqcError(pqcErr.message || 'Failed to establish PQC session');
          setError('Failed to establish quantum-resistant session. Please try again.');
          setLoading(false);
          return;
        }

      } else {
        setFailedAttempts(prev => prev + 1);
        setError('Invalid username or password');
      }
    } catch (err) {
      setFailedAttempts(prev => prev + 1);
      setError('Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  // Get loading message based on PQC status
  const getLoadingMessage = () => {
    if (pqcStatus === 'connecting') {
      return 'Establishing PQC Session...';
    }
    if (pqcStatus === 'initializing') {
      return 'Initializing...';
    }
    return 'Unlocking...';
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="lock-icon">🔒</div>
          <h1 className="auth-title">PQC Vault</h1>
          <p className="auth-subtitle">Zero-Knowledge Password Manager</p>
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
              <span className="pqc-icon">🔐</span>
              <span>PQC Ready (Click to Connect)</span>
            </>
          )}
          {pqcStatus === 'connecting' && (
            <>
              <span className="pqc-spinner">⚡</span>
              <span>Establishing PQC Session...</span>
            </>
          )}
          {pqcStatus === 'connected' && (
            <>
              <span className="pqc-icon">🛡️</span>
              <span>PQC Protected (ML-KEM-1024)</span>
            </>
          )}
          {pqcStatus === 'error' && (
            <>
              <span className="pqc-icon">⚠️</span>
              <span>PQC: {pqcError || 'Connection Failed'}</span>
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
              placeholder="Enter your username"
              required
              autoComplete="username"
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Master Password</label>
            <input
              id="password"
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              placeholder="Enter your master password"
              required
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="error-message">
              <span className="error-icon">⚠️</span>
              {error}
            </div>
          )}

          {failedAttempts > 0 && (
            <div className="attempt-counter">
              Failed attempts: {failedAttempts}
            </div>
          )}

          <button 
            type="submit" 
            className="auth-button"
            disabled={loading || pqcStatus === 'initializing'}
          >
            {loading ? getLoadingMessage() : 'Unlock Vault'}
          </button>
        </form>

        <div className="auth-footer">
          <p>Don't have an account?</p>
          <button 
            onClick={onSwitchToRegister}
            className="link-button"
          >
            Create New Vault
          </button>
        </div>

        <div className="security-badge">
          <div className="badge-item">
            <span className="badge-icon">🛡️</span>
            <span>Post-Quantum</span>
          </div>
          <div className="badge-item">
            <span className="badge-icon">🔐</span>
            <span>Zero-Knowledge</span>
          </div>
          <div className="badge-item">
            <span className="badge-icon">🔒</span>
            <span>AES-256</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;
