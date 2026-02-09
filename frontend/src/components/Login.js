/**
 * Login Component
 * Handles user authentication with zero-knowledge architecture
 */
import React, { useState } from 'react';
import { authAPI } from '../utils/api';
import { deriveVaultKey } from '../utils/crypto';
import '../styles/Auth.css';

function Login({ onLoginSuccess, onSwitchToRegister }) {
  const [username, setUsername] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [failedAttempts, setFailedAttempts] = useState(0);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Login to get salt
      const response = await authAPI.login(username, masterPassword);

      if (response.success) {
        setFailedAttempts(0);
        
        // Debug logging
        console.log('Login - salt received:', response.salt ? 'present' : 'missing');
        console.log('Login - salt length:', response.salt?.length);
        
        // Derive vault key client-side
        const vaultKey = await deriveVaultKey(masterPassword, response.salt);
        console.log('Login - vaultKey derived:', vaultKey ? 'present' : 'missing');

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

  return (
    <div className="auth-container">
      <div className="auth-card">
        <div className="auth-header">
          <div className="lock-icon">🔒</div>
          <h1 className="auth-title">PQC Vault</h1>
          <p className="auth-subtitle">Zero-Knowledge Password Manager</p>
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
            disabled={loading}
          >
            {loading ? 'Unlocking...' : 'Unlock Vault'}
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
