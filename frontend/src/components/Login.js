/**
 * Login Component
 * Handles user authentication with zero-knowledge architecture
 */
import React, { useState } from 'react';
import { authAPI } from '../utils/api';
import { createChallengeResponse, deriveVaultKey } from '../utils/crypto';
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
      // Step 1: Request one-time challenge + salt
      const challengeData = await authAPI.getLoginChallenge(username);
      const salt = challengeData?.salt;
      const challenge = challengeData?.challenge;
      const challengeId = challengeData?.challengeId;
      if (!challengeData?.success || !salt || !challenge || !challengeId) {
        throw new Error(challengeData?.error || 'Failed to start login flow');
      }

      // Step 2: Derive vault key and generate challenge response locally
      const vaultKey = await deriveVaultKey(masterPassword, salt);
      const challengeResponse = await createChallengeResponse(vaultKey, challenge);

      // Step 3: Complete login with proof (never send master password)
      const response = await authAPI.login(username, challengeId, challengeResponse);
      if (response.success) {
        setFailedAttempts(0);

        // Pass user data and vault key to parent
        onLoginSuccess({
          userId: response.userId,
          username: response.username,
          salt: response.salt || salt
        }, vaultKey);
      } else {
        setFailedAttempts(prev => prev + 1);
        if (response.retry_after) {
          setError(`Too many failed attempts. Try again in ${response.retry_after} seconds.`);
        } else {
          setError(response.error || 'Invalid username or password');
        }
      }
    } catch (err) {
      setFailedAttempts(prev => prev + 1);
      const apiError = err.response?.data?.error;
      const retryAfter = err.response?.data?.retry_after;
      if (retryAfter) {
        setError(`Too many failed attempts. Try again in ${retryAfter} seconds.`);
      } else {
        setError(apiError || 'Login failed. Please try again.');
      }
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
