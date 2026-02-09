/**
 * Dashboard Component
 * Main interface for managing passwords
 */
import React, { useState, useEffect, useCallback, useRef } from 'react';
import AddPassword from './AddPassword';
import StoredPasswords from './StoredPasswords';
import CryptoView from './CryptoView';
import '../styles/Dashboard.css';

const VAULT_LOCK_TIMEOUT = 5 * 60 * 1000; // 5 minutes in milliseconds

function Dashboard({ user, vaultKey, onLogout, onLockVault }) {
  const [currentView, setCurrentView] = useState('add'); // 'add', 'stored', 'crypto'
  const [isLocked, setIsLocked] = useState(false);
  const idleTimeoutRef = useRef(null);
  const lastActivityRef = useRef(Date.now());

  // Track user activity
  const resetIdleTimer = useCallback(() => {
    lastActivityRef.current = Date.now();
    if (idleTimeoutRef.current) {
      clearTimeout(idleTimeoutRef.current);
    }
    
    idleTimeoutRef.current = setTimeout(() => {
      const idleTime = Date.now() - lastActivityRef.current;
      if (idleTime >= VAULT_LOCK_TIMEOUT) {
        handleVaultLock();
      }
    }, VAULT_LOCK_TIMEOUT);
  }, []);

  // Handle vault lock
  const handleVaultLock = useCallback(() => {
    if (idleTimeoutRef.current) {
      clearTimeout(idleTimeoutRef.current);
    }
    setIsLocked(true);
    onLockVault();
  }, [onLockVault]);

  // Set up activity listeners
  useEffect(() => {
    const activityEvents = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    const handleActivity = () => {
      if (!isLocked) {
        resetIdleTimer();
      }
    };

    activityEvents.forEach(event => {
      document.addEventListener(event, handleActivity);
    });

    // Initial timer setup
    resetIdleTimer();

    return () => {
      activityEvents.forEach(event => {
        document.removeEventListener(event, handleActivity);
      });
      if (idleTimeoutRef.current) {
        clearTimeout(idleTimeoutRef.current);
      }
    };
  }, [resetIdleTimer, isLocked]);

  // If vault is locked, show lock screen
  if (isLocked) {
    return (
      <div className="dashboard-lock-screen">
        <div className="lock-message">
          <div className="lock-icon">🔒</div>
          <h2>Vault Locked</h2>
          <p>Your vault has been automatically locked due to inactivity.</p>
          <p>Please log in again to continue.</p>
          <button onClick={onLogout} className="unlock-button">
            Return to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="vault-icon">🔒</div>
          <h2>PQC Vault</h2>
        </div>

        <nav className="sidebar-nav">
          <button 
            className={`nav-item ${currentView === 'add' ? 'active' : ''}`}
            onClick={() => setCurrentView('add')}
          >
            <span className="nav-icon">➕</span>
            <span>Add Password</span>
          </button>

          <button 
            className={`nav-item ${currentView === 'stored' ? 'active' : ''}`}
            onClick={() => setCurrentView('stored')}
          >
            <span className="nav-icon">📁</span>
            <span>Stored Passwords</span>
          </button>

          <button 
            className={`nav-item ${currentView === 'crypto' ? 'active' : ''}`}
            onClick={() => setCurrentView('crypto')}
          >
            <span className="nav-icon">🔧</span>
            <span>Crypto View</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="user-profile">
            <div className="user-avatar">👤</div>
            <div className="user-details">
              <p className="user-name">{user.username}</p>
              <p className="user-status">Vault Unlocked</p>
            </div>
          </div>

          <div className="sidebar-actions">
            <button onClick={handleVaultLock} className="lock-button">
              <span>🔒</span>
              Lock Vault
            </button>
            <button onClick={onLogout} className="logout-button">
              <span>🚪</span>
              Sign Out
            </button>
          </div>
        </div>
      </div>

      <div className="main-content">
        {currentView === 'add' && (
          <AddPassword user={user} vaultKey={vaultKey} />
        )}

        {currentView === 'stored' && (
          <StoredPasswords user={user} vaultKey={vaultKey} />
        )}

        {currentView === 'crypto' && (
          <CryptoView user={user} vaultKey={vaultKey} />
        )}
      </div>
    </div>
  );
}

export default Dashboard;
