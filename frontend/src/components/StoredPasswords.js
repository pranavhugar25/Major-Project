/**
 * StoredPasswords Component
 * Display and manage stored encrypted passwords
 */
import React, { useState, useEffect } from 'react';
import { passwordAPI } from '../utils/api';
import { decryptPassword } from '../utils/crypto';
import '../styles/StoredPasswords.css';

function StoredPasswords({ user, vaultKey }) {
  const [passwords, setPasswords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revealedPasswords, setRevealedPasswords] = useState({});
  const [copiedId, setCopiedId] = useState(null);

  useEffect(() => {
    fetchPasswords();
  }, []);

  const fetchPasswords = async () => {
    try {
      const response = await passwordAPI.getAllPasswords(user.userId);
      
      if (response.success) {
        setPasswords(response.passwords || []);
      } else {
        setError(response.error || 'Failed to fetch passwords');
      }
    } catch (err) {
      setError('Failed to load passwords');
    } finally {
      setLoading(false);
    }
  };

  const handleRevealPassword = (passwordId, encryptedPassword, iv) => {
    try {
      const decrypted = decryptPassword(encryptedPassword, iv, vaultKey);
      setRevealedPasswords(prev => ({
        ...prev,
        [passwordId]: decrypted
      }));
    } catch (err) {
      alert('Failed to decrypt password. Your vault key may be incorrect.');
    }
  };

  const handleHidePassword = (passwordId) => {
    setRevealedPasswords(prev => {
      const updated = { ...prev };
      delete updated[passwordId];
      return updated;
    });
  };

  const handleCopyPassword = async (passwordId, encryptedPassword, iv) => {
    try {
      const decrypted = decryptPassword(encryptedPassword, iv, vaultKey);
      await navigator.clipboard.writeText(decrypted);
      setCopiedId(passwordId);
      setTimeout(() => setCopiedId(null), 2000);
    } catch (err) {
      alert('Failed to copy password');
    }
  };

  const handleDelete = async (passwordId) => {
    if (!window.confirm('Are you sure you want to delete this password?')) {
      return;
    }

    try {
      const response = await passwordAPI.deletePassword(passwordId);
      
      if (response.success) {
        setPasswords(prev => prev.filter(p => p.passwordId !== passwordId));
      } else {
        alert('Failed to delete password');
      }
    } catch (err) {
      alert('Failed to delete password');
    }
  };

  if (loading) {
    return (
      <div className="stored-passwords-container">
        <div className="loading">Loading passwords...</div>
      </div>
    );
  }

  return (
    <div className="stored-passwords-container">
      <div className="content-header">
        <h1>Stored Passwords</h1>
        <p className="subtitle">
          {passwords.length} {passwords.length === 1 ? 'password' : 'passwords'} encrypted and stored
        </p>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {passwords.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">📭</div>
          <h2>No Passwords Yet</h2>
          <p>Start adding passwords to your vault to see them here</p>
        </div>
      ) : (
        <div className="passwords-grid">
          {passwords.map(pwd => (
            <div key={pwd.passwordId} className="password-card">
              <div className="card-header">
                <div className="site-icon">🌐</div>
                <div className="site-info">
                  <h3 className="site-url">{pwd.siteUrl}</h3>
                  <p className="site-username">{pwd.siteUsername}</p>
                </div>
              </div>

              <div className="card-body">
                <div className="password-field">
                  <label>Password</label>
                  <div className="password-display">
                    {revealedPasswords[pwd.passwordId] ? (
                      <span className="revealed-password">
                        {revealedPasswords[pwd.passwordId]}
                      </span>
                    ) : (
                      <span className="hidden-password">••••••••••••</span>
                    )}
                  </div>
                </div>

                <div className="card-actions">
                  {revealedPasswords[pwd.passwordId] ? (
                    <button 
                      onClick={() => handleHidePassword(pwd.passwordId)}
                      className="action-button hide-button"
                      title="Hide password"
                    >
                      👁️‍🗨️ Hide
                    </button>
                  ) : (
                    <button 
                      onClick={() => handleRevealPassword(pwd.passwordId, pwd.encryptedPassword, pwd.iv)}
                      className="action-button reveal-button"
                      title="Show password"
                    >
                      👁️ Show
                    </button>
                  )}

                  <button 
                    onClick={() => handleCopyPassword(pwd.passwordId, pwd.encryptedPassword, pwd.iv)}
                    className="action-button copy-button"
                    title="Copy password"
                  >
                    {copiedId === pwd.passwordId ? '✅ Copied' : '📋 Copy'}
                  </button>

                  <button 
                    onClick={() => handleDelete(pwd.passwordId)}
                    className="action-button delete-button"
                    title="Delete password"
                  >
                    🗑️ Delete
                  </button>
                </div>
              </div>

              <div className="card-footer">
                <small>Encrypted with AES-256-GCM</small>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default StoredPasswords;
