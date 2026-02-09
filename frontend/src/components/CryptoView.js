/**
 * CryptoView Component
 * Displays encrypted data to demonstrate zero-knowledge architecture
 */
import React, { useState, useEffect } from 'react';
import { passwordAPI } from '../utils/api';
import '../styles/CryptoView.css';

function CryptoView({ user }) {
  const [cryptoData, setCryptoData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchCryptoView();
  }, []);

  const fetchCryptoView = async () => {
    try {
      const response = await passwordAPI.getCryptoView(user.userId);
      console.log('CryptoView - response:', response);
      
      if (response.success) {
        setCryptoData(response);
      } else {
        setError(response.error || 'Failed to fetch crypto view');
      }
    } catch (err) {
      console.error('CryptoView - error:', err);
      setError('Failed to load crypto view');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="crypto-view-container">
        <div className="loading">Loading crypto view...</div>
      </div>
    );
  }

  return (
    <div className="crypto-view-container">
      <div className="content-header">
        <h1>Cryptographic Transparency</h1>
        <p className="subtitle">
          This view shows exactly what the server stores - only encrypted data
        </p>
      </div>

      {error && (
        <div className="error-message">
          <span className="error-icon">⚠️</span>
          {error}
        </div>
      )}

      {cryptoData && (
        <div className="crypto-content">
          <div className="info-banner">
            <span className="banner-icon">ℹ️</span>
            <div>
              <strong>Zero-Knowledge Proof</strong>
              <p>
                The server only stores encrypted ciphertext. Without your vault key 
                (derived from your master password), this data is mathematically 
                impossible to decrypt.
              </p>
            </div>
          </div>

          <div className="crypto-section">
            <h2>User Account Data</h2>
            <div className="data-grid">
              <div className="data-item">
                <label>Username</label>
                <code>{cryptoData.username}</code>
              </div>
              <div className="data-item">
                <label>User ID</label>
                <code>{cryptoData.userId}</code>
              </div>
              <div className="data-item">
                <label>Salt (for PBKDF2)</label>
                <code className="truncated">{cryptoData.salt}</code>
              </div>
              <div className="data-item">
                <label>Master Password Hash</label>
                <code className="truncated">{cryptoData.masterPasswordHash}</code>
                <small>Server only stores hash, not actual password</small>
              </div>
            </div>
          </div>

          {cryptoData.passwords && cryptoData.passwords.length > 0 && (
            <div className="crypto-section">
              <h2>Encrypted Passwords</h2>
              <p className="section-note">{cryptoData.note}</p>
              
              {cryptoData.passwords.map((pwd, index) => (
                <div key={index} className="encrypted-password-card">
                  <div className="card-title">
                    <span className="lock-icon">🔒</span>
                    <strong>{pwd.siteUrl}</strong>
                  </div>
                  
                  <div className="encrypted-data">
                    <div className="data-row">
                      <label>Site Username:</label>
                      <code>{pwd.siteUsername}</code>
                    </div>
                    
                    <div className="data-row">
                      <label>Encrypted Password (truncated):</label>
                      <code className="ciphertext">{pwd.encryptedPassword}</code>
                    </div>
                    
                    <div className="data-row">
                      <label>Initialization Vector (IV):</label>
                      <code className="truncated">{pwd.iv}</code>
                    </div>
                    
                    <div className="data-row">
                      <label>Authentication Tag:</label>
                      <code className="truncated">{pwd.authTag}</code>
                    </div>
                    
                    <div className="note-box">
                      <span className="note-icon">⚠️</span>
                      <small>{pwd.note}</small>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {(!cryptoData.passwords || cryptoData.passwords.length === 0) && (
            <div className="empty-state">
              <div className="empty-icon">🔐</div>
              <h3>No Encrypted Passwords</h3>
              <p>Add some passwords to see their encrypted form here</p>
            </div>
          )}

          <div className="crypto-section">
            <h2>Security Architecture</h2>
            <div className="architecture-grid">
              <div className="arch-card">
                <span className="arch-icon">🔑</span>
                <h3>Key Derivation</h3>
                <p>PBKDF2 with 600,000 iterations generates your vault key from master password + salt</p>
              </div>
              
              <div className="arch-card">
                <span className="arch-icon">🔐</span>
                <h3>Encryption</h3>
                <p>AES-256-GCM authenticated encryption happens entirely in your browser</p>
              </div>
              
              <div className="arch-card">
                <span className="arch-icon">🛡️</span>
                <h3>Post-Quantum</h3>
                <p>ML-KEM and ML-DSA protect against future quantum computing threats</p>
              </div>
              
              <div className="arch-card">
                <span className="arch-icon">🚫</span>
                <h3>Zero-Knowledge</h3>
                <p>Server never sees your master password or vault key</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default CryptoView;
