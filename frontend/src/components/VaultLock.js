/**
 * VaultLock Component
 * Shown when vault is locked, requires master password to unlock
 */
import React, { useState } from 'react';
import { deriveVaultKey } from '../utils/crypto';
import '../styles/VaultLock.css';

function VaultLock({ user, onUnlock, onLogout }) {
  const [masterPassword, setMasterPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleUnlock = (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Derive vault key from master password and stored salt
      const vaultKey = deriveVaultKey(masterPassword, user.salt);
      
      // Pass vault key to parent component
      onUnlock(vaultKey);
    } catch (err) {
      setError('Failed to unlock vault. Please check your master password.');
      setLoading(false);
    }
  };

  return (
    <div className="vault-lock-container">
      <div className="vault-lock-card">
        <div className="lock-animation">
          <div className="lock-body">🔒</div>
          <div className="lock-shimmer"></div>
        </div>

        <h1 className="vault-title">PQC Vault Locked</h1>
        <p className="vault-subtitle">
          Enter your master password to derive the decryption keys.
        </p>

        <div className="user-info">
          <span className="user-icon">👤</span>
          <span className="username">{user.username}</span>
        </div>

        <form onSubmit={handleUnlock} className="unlock-form">
          <div className="form-group">
            <input
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              placeholder="Enter Master Password"
              required
              autoFocus
              autoComplete="current-password"
            />
          </div>

          {error && (
            <div className="error-message">
              <span className="error-icon">⚠️</span>
              {error}
            </div>
          )}

          <button 
            type="submit" 
            className="unlock-button"
            disabled={loading}
          >
            {loading ? 'Unlocking...' : 'Unlock Vault'}
          </button>
        </form>

        <button onClick={onLogout} className="logout-link">
          Sign out
        </button>

        <div className="security-info">
          <div className="info-item">
            <span className="info-icon">🔐</span>
            <div>
              <strong>Zero-Knowledge</strong>
              <p>Vault key derived locally</p>
            </div>
          </div>
          <div className="info-item">
            <span className="info-icon">🛡️</span>
            <div>
              <strong>Post-Quantum</strong>
              <p>Protected against future threats</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default VaultLock;
