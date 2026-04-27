/**
 * AddPassword Component
 * Interface for adding new encrypted passwords
 */
import React, { useState } from 'react';
import { passwordAPI } from '../utils/api';
import { encryptPassword, generatePassword } from '../utils/crypto';
import '../styles/AddPassword.css';

function AddPassword({ user, vaultKey }) {
  const [siteUrl, setSiteUrl] = useState('');
  const [siteUsername, setSiteUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');
  const [error, setError] = useState('');

  const handleGeneratePassword = () => {
    const generated = generatePassword(16, {
      includeLowercase: true,
      includeUppercase: true,
      includeNumbers: true,
      includeSymbols: true
    });
    setPassword(generated);
    setShowPassword(true);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    setLoading(true);

    try {
      
      // Encrypt password client-side
      console.log('AddPassword - vaultKey:', vaultKey ? 'present' : 'missing');
      console.log('AddPassword - password:', password ? 'present' : 'missing');
      console.log('AddPassword - salt:', user.salt ? 'present' : 'missing');
      const { encryptedPassword, iv, authTag } = await encryptPassword(password, vaultKey);
      console.log('AddPassword - encrypted:', { encryptedPassword: !!encryptedPassword, ivLength: iv?.length, authTag: authTag });

      // Send encrypted data to server
      const response = await passwordAPI.addPassword({
        siteUrl: siteUrl,
        siteUsername: siteUsername,
        encryptedPassword: encryptedPassword,
        iv: iv,
        authTag: authTag
      });

      if (response.success) {
        setSuccess('Password saved successfully! 🎉');
        // Reset form
        setSiteUrl('');
        setSiteUsername('');
        setPassword('');
        setShowPassword(false);
        
        // Clear success message after 3 seconds
        setTimeout(() => setSuccess(''), 3000);
      } else {
        setError(response.error || 'Failed to save password');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to save password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="add-password-container">
      <div className="content-header">
        <h1>Add Password</h1>
        <p className="subtitle">All passwords are encrypted locally before storage</p>
      </div>

      <form onSubmit={handleSubmit} className="add-password-form">
        <div className="form-group">
          <label htmlFor="site-url">Site URL</label>
          <input
            id="site-url"
            type="text"
            value={siteUrl}
            onChange={(e) => setSiteUrl(e.target.value)}
            placeholder="e.g., google.com, facebook.com"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="site-username">Username</label>
          <input
            id="site-username"
            type="text"
            value={siteUsername}
            onChange={(e) => setSiteUsername(e.target.value)}
            placeholder="Your username or email for this site"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password</label>
          <div className="password-input-group">
            <input
              id="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter or generate a password"
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="icon-button"
              title={showPassword ? 'Hide password' : 'Show password'}
            >
              {showPassword ? '👁️' : '👁️‍🗨️'}
            </button>
          </div>
        </div>

        <button 
          type="button" 
          onClick={handleGeneratePassword}
          className="generate-button"
        >
          🎲 Generate Strong Password
        </button>

        {success && (
          <div className="success-message">
            <span className="success-icon">✅</span>
            {success}
          </div>
        )}

        {error && (
          <div className="error-message">
            <span className="error-icon">⚠️</span>
            {error}
          </div>
        )}

        <button 
          type="submit" 
          className="save-button"
          disabled={loading}
        >
          {loading ? 'Encrypting & Saving...' : '💾 Save Password'}
        </button>
      </form>

      <div className="encryption-info">
        <div className="info-card">
          <span className="info-icon">🔐</span>
          <div>
            <h3>Client-Side Encryption</h3>
            <p>Your password is encrypted using AES-256-GCM in your browser before transmission</p>
          </div>
        </div>
        <div className="info-card">
          <span className="info-icon">🛡️</span>
          <div>
            <h3>Post-Quantum Secure</h3>
            <p>Communication protected with ML-KEM and ML-DSA algorithms</p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AddPassword;
