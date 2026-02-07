/**
 * Dashboard Component
 * Main interface for managing passwords
 */
import React, { useState } from 'react';
import AddPassword from './AddPassword';
import StoredPasswords from './StoredPasswords';
import CryptoView from './CryptoView';
import '../styles/Dashboard.css';

function Dashboard({ user, vaultKey, onLogout, onLockVault }) {
  const [currentView, setCurrentView] = useState('add'); // 'add', 'stored', 'crypto'

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
            <button onClick={onLockVault} className="lock-button">
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
          <CryptoView user={user} />
        )}
      </div>
    </div>
  );
}

export default Dashboard;
