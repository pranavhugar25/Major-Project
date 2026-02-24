/**
 * Main App Component
 * Manages authentication state and vault locking
 */
import React, { useState, useEffect } from 'react';
import './styles/App.css';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import VaultLock from './components/VaultLock';
import { secureZeroize } from './utils/crypto';
import { clearAuthTokens, isAuthenticated } from './utils/api';

function App() {
  const [currentView, setCurrentView] = useState('login'); // 'login', 'register', 'vault-lock', 'dashboard'
  const [user, setUser] = useState(null);
  const [vaultKey, setVaultKey] = useState(null);
  const [isVaultLocked, setIsVaultLocked] = useState(false);

  // Check for existing session on mount
  useEffect(() => {
    const storedUser = sessionStorage.getItem('pqc_user');
    if (storedUser && isAuthenticated()) {
      const userData = JSON.parse(storedUser);
      setUser(userData);
      setIsVaultLocked(true);
      setCurrentView('vault-lock');
      return;
    }
    sessionStorage.removeItem('pqc_user');
    clearAuthTokens();
  }, []);

  // Handle successful login
  const handleLoginSuccess = (userData, derivedVaultKey) => {
    setUser(userData);
    setVaultKey(derivedVaultKey);
    setIsVaultLocked(false);
    sessionStorage.setItem('pqc_user', JSON.stringify(userData));
    setCurrentView('dashboard');
  };

  // Handle successful registration
  const handleRegisterSuccess = (userData, derivedVaultKey) => {
    setUser(userData);
    setVaultKey(derivedVaultKey);
    setIsVaultLocked(false);
    sessionStorage.setItem('pqc_user', JSON.stringify(userData));
    setCurrentView('dashboard');
  };

  // Handle vault unlock
  const handleVaultUnlock = (derivedVaultKey) => {
    setVaultKey(derivedVaultKey);
    setIsVaultLocked(false);
    setCurrentView('dashboard');
  };

  // Handle logout
  const handleLogout = () => {
    // Securely clear vault key from memory before logout
    if (vaultKey) {
      try {
        const keyBytes = Uint8Array.from(atob(vaultKey), c => c.charCodeAt(0));
        secureZeroize(keyBytes);
      } catch (e) {
        console.error('Failed to zeroize vault key');
      }
    }
    setUser(null);
    setVaultKey(null);
    setIsVaultLocked(false);
    sessionStorage.removeItem('pqc_user');
    clearAuthTokens();
    setCurrentView('login');
  };

  // Handle lock vault
  const handleLockVault = () => {
    setVaultKey(null);
    setIsVaultLocked(true);
    setCurrentView('vault-lock');
  };

  // Auto-lock after 15 minutes of inactivity
  useEffect(() => {
    let inactivityTimeout;
    
    const resetInactivityTimer = () => {
      if (inactivityTimeout) {
        clearTimeout(inactivityTimeout);
      }
      if (!isVaultLocked && vaultKey) {
        inactivityTimeout = setTimeout(() => {
          handleLockVault();
        }, 15 * 60 * 1000); // 15 minutes
      }
    };
    
    // Listen for user activity
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    events.forEach(event => {
      window.addEventListener(event, resetInactivityTimer);
    });
    
    resetInactivityTimer();
    
    return () => {
      if (inactivityTimeout) {
        clearTimeout(inactivityTimeout);
      }
      events.forEach(event => {
        window.removeEventListener(event, resetInactivityTimer);
      });
    };
  }, [vaultKey, isVaultLocked]);

  return (
    <div className="app">
      {currentView === 'login' && (
        <Login 
          onLoginSuccess={handleLoginSuccess}
          onSwitchToRegister={() => setCurrentView('register')}
        />
      )}

      {currentView === 'register' && (
        <Register 
          onRegisterSuccess={handleRegisterSuccess}
          onSwitchToLogin={() => setCurrentView('login')}
        />
      )}

      {currentView === 'vault-lock' && user && (
        <VaultLock 
          user={user}
          onUnlock={handleVaultUnlock}
          onLogout={handleLogout}
        />
      )}

      {currentView === 'dashboard' && user && vaultKey && (
        <Dashboard 
          user={user}
          vaultKey={vaultKey}
          onLogout={handleLogout}
          onLockVault={handleLockVault}
        />
      )}
    </div>
  );
}

export default App;
