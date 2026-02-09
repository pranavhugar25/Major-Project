/**
 * Register Component
 * Handles new user registration with zero-knowledge architecture
 */
import React, { useState } from 'react';
import { authAPI } from '../utils/api';
import { deriveVaultKey, calculatePasswordStrength } from '../utils/crypto';
import '../styles/Auth.css';

function Register({ onRegisterSuccess, onSwitchToLogin }) {
  const [username, setUsername] = useState('');
  const [masterPassword, setMasterPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState(null);

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

    setLoading(true);

    try {
      // Register user
      const response = await authAPI.register(username, masterPassword);

      if (response.success) {
        // Derive vault key client-side
        const vaultKey = await deriveVaultKey(masterPassword, response.salt);

        // Pass user data and vault key to parent
        onRegisterSuccess({
          userId: response.userId,
          username: response.username,
          salt: response.salt
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
            disabled={loading}
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
