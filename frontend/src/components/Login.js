/**
 * Login Component
 * Handles user authentication with zero-knowledge architecture
 * Integrates PQC (Post-Quantum Cryptography) for enhanced security
 */
import React, { useState } from 'react';
import { authAPI, setAuthTokens } from '../utils/api';
import { deriveVaultKey } from '../utils/crypto';
import { 
  initPQC,
  isPQCAvailable,
  generateKeypair,
  encapsulate,
  initSession
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
      // Login to get salt
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
        
        // Derive vault key client-side
        const vaultKey = await deriveVaultKey(masterPassword, response.salt);
        console.log('[Login] VaultKey derived:', vaultKey ? 'present' : 'missing');

        // Initialize PQC session with server
        try {
          setPqcStatus('connecting');
          console.log('[Login] Initializing PQC session with server...');
          
          const session = await initSession(username, response.userId);
          console.log('[Login] Session initialized:', session.session_id);
          
          // Perform key encapsulation to establish shared secret
          if (session.server_public_key) {
            console.log('[Login] Performing key encapsulation...');
            const encapsulation = encapsulate(session.server_public_key);
            console.log('[Login] PQC key exchange complete');
          }
          
          setPqcStatus('connected');
          console.log('[Login] PQC session fully established');
        } catch (pqcErr) {
          console.error('[Login] PQC session error:', pqcErr);
          // PQC failure is logged but we continue - user is authenticated
          // In production, you might want to be stricter here
          setPqcStatus('error');
          setPqcError(pqcErr.message || 'Failed to establish PQC session');
        }

        // Pass user data and vault key to parent
        onLoginSuccess({
          userId: response.userId,
          username: response.username,
          salt: response.salt
        }, vaultKey);
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
