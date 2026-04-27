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
import './utils/authDebug'; // Import auth debugging utility

function App() {
  const [currentView, setCurrentView] = useState('login'); // 'login', 'register', 'vault-lock', 'dashboard'
  const [user, setUser] = useState(null);
  const [vaultKey, setVaultKey] = useState(null);
  const [isVaultLocked, setIsVaultLocked] = useState(false);

  // Check for existing session on mount
  useEffect(() => {
    const storedUser = sessionStorage.getItem('pqc_user');
    if (storedUser) {
      const userData = JSON.parse(storedUser);
      setUser(userData);
      setIsVaultLocked(true);
      setCurrentView('vault-lock');
    }
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
    setUser(null);
    setVaultKey(null);
    setIsVaultLocked(false);
    sessionStorage.removeItem('pqc_user');
    setCurrentView('login');
  };

  // Handle lock vault
  const handleLockVault = () => {
    setVaultKey(null);
    setIsVaultLocked(true);
    setCurrentView('vault-lock');
  };

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
