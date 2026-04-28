/**
 * API service for communicating with the backend
 * JWT-based authentication with automatic token management
 */
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Token storage keys
const ACCESS_TOKEN_KEY = 'pqc_access_token';
const REFRESH_TOKEN_KEY = 'pqc_refresh_token';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  timeout: 10000
});

// ============================================
// Request Interceptor - Add JWT Token
// ============================================
api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// ============================================
// Response Interceptor - Handle Auth Errors
// ============================================
api.interceptors.response.use(
  (response) => {
    return response;
  },
  async (error) => {
    const originalRequest = error.config;
    
    // Handle 401 errors - attempt token refresh
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      
      const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
      if (refreshToken) {
        try {
          // Attempt to refresh the access token
          const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
            refresh_token: refreshToken
          });
          
          if (response.data.success) {
            // Store new tokens
            setAuthTokens(response.data);
            
            // Retry original request with new token
            originalRequest.headers.Authorization = `Bearer ${response.data.access_token}`;
            return api(originalRequest);
          }
        } catch (refreshError) {
          // Refresh failed - clear tokens and redirect to login
          clearAuthTokens();
          redirectToLogin();
          return Promise.reject(refreshError);
        }
      } else {
        // No refresh token - redirect to login
        clearAuthTokens();
        redirectToLogin();
      }
    }
    
    return Promise.reject(error);
  }
);

// ============================================
// Token Management Functions
// ============================================

/**
 * Store authentication tokens
 * @param {object} tokenData - Object containing access_token, refresh_token, expires_in
 */
export const setAuthTokens = (tokenData) => {
  if (tokenData.access_token) {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, tokenData.access_token);
  }
  if (tokenData.refresh_token) {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, tokenData.refresh_token);
  }
};

/**
 * Clear authentication tokens
 */
export const clearAuthTokens = () => {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
};

/**
 * Get access token
 * @returns {string|null}
 */
export const getAccessToken = () => {
  return sessionStorage.getItem(ACCESS_TOKEN_KEY);
};

/**
 * Check if user is authenticated
 * @returns {boolean}
 */
export const isAuthenticated = () => {
  return !!getAccessToken();
};

/**
 * Redirect to login page
 */
const redirectToLogin = () => {
  // Clear any cached user data
  sessionStorage.removeItem('pqc_user');
  
  // Redirect if in browser
  if (typeof window !== 'undefined' && !window.location.pathname.includes('/login')) {
    window.location.href = '/login';
  }
};

/**
 * Handle successful login
 * @param {object} loginData - Response data from login API
 */
export const handleLoginSuccess = (loginData) => {
  // Store tokens
  setAuthTokens({
    access_token: loginData.access_token,
    refresh_token: loginData.refresh_token,
    expires_in: loginData.expires_in
  });
  
  // Store minimal user data (not the vault key!)
  const userData = {
    userId: loginData.userId,
    username: loginData.username,
    salt: loginData.salt
  };
  sessionStorage.setItem('pqc_user', JSON.stringify(userData));
};

/**
 * Handle logout
 */
export const handleLogout = () => {
  clearAuthTokens();
  sessionStorage.removeItem('pqc_user');
  redirectToLogin();
};

// ============================================
// Authentication APIs
// ============================================
export const authAPI = {
  /**
   * Register a new user
   * @param {string} username - Username
   * @param {string} masterPassword - Master password
   * @param {string} pqcPublicKey - Optional PQC public key (ML-KEM-1024)
   * @returns {Promise<object>} Response with userId and salt
   */
  register: async (username, masterPassword, pqcPublicKey = null) => {
    const payload = {
      username,
      masterPassword
    };
    
    // Add PQC public key if provided
    if (pqcPublicKey) {
      payload.pqcPublicKey = pqcPublicKey;
      payload.pqcAlgorithm = 'ML-KEM-1024';
    }
    
    const response = await api.post('/auth/register', payload);
    return response.data;
  },

  /**
   * Login user - returns JWT tokens
   * @param {string} username - Username
   * @param {string} masterPassword - Master password
   * @returns {Promise<object>} Response with tokens, userId, and salt
   */
  login: async (username, masterPassword) => {
    const response = await api.post('/auth/login', {
      username,
      masterPassword
    });
    
    if (response.data.success) {
      handleLoginSuccess(response.data);
    }
    
    return response.data;
  },

  /**
   * Refresh access token
   * @param {string} refreshToken - Refresh token
   * @returns {Promise<object>} New access token
   */
  refresh: async (refreshToken) => {
    const response = await axios.post(`${API_BASE_URL}/auth/refresh`, {
      refresh_token: refreshToken
    });
    return response.data;
  },

  /**
   * Verify if current token is valid
   * @returns {Promise<object>} Token validity status
   */
  verify: async () => {
    const response = await api.get('/auth/verify');
    return response.data;
  },

  /**
   * Logout user
   * @returns {Promise<object>} Logout status
   */
  logout: async () => {
    try {
      await api.post('/auth/logout');
    } finally {
      handleLogout();
    }
  },

  /**
   * Check if username is available
   * @param {string} username - Username to check
   * @returns {Promise<object>} Availability status
   */
  checkUsername: async (username) => {
    const response = await api.post('/auth/check-username', { username });
    return response.data;
  },

  /**
   * Get salt for a username
   * @param {string} username - Username
   * @returns {Promise<object>} Salt data
   */
   getSalt: async (username) => {
     const response = await api.post('/auth/get-salt', { username });
     return response.data;
   },

   /**
    * Confirm PQC session with client's public key
    * @param {string} sessionId - Session ID
    * @param {object} clientKeyData - Client public key data
    * @returns {Promise<object>} Confirmation response
    */
   confirmPQCSession: async (sessionId, clientKeyData) => {
     const response = await api.post('/auth/pqc/confirm', {
       session_id: sessionId,
       client_public_key: clientKeyData.client_public_key
     });
     return response.data;
   }
 };

// ============================================
// Password Management APIs
// ============================================
export const passwordAPI = {
  /**
   * Add or update encrypted password
   * @param {object} passwordData - Encrypted password data
   * @returns {Promise<object>} Success status
   */
  addPassword: async (passwordData) => {
    const response = await api.post('/passwords/add', passwordData);
    return response.data;
  },

  /**
   * Get all passwords for authenticated user
   * @returns {Promise<object>} Array of encrypted passwords
   */
  getAllPasswords: async () => {
    const response = await api.post('/passwords/get-all', {});
    return response.data;
  },

  /**
   * Delete a password
   * @param {string} passwordId - Password ID to delete
   * @returns {Promise<object>} Success status
   */
  deletePassword: async (passwordId) => {
    const response = await api.post('/passwords/delete', { passwordId });
    return response.data;
  },

  /**
   * Get crypto view (for transparency)
   * @returns {Promise<object>} Encrypted data view
   */
  getCryptoView: async () => {
    const response = await api.post('/passwords/get-crypto-view', {});
    return response.data;
  }
};

// ============================================
// Benchmark APIs
// ============================================
export const benchmarkAPI = {
  /**
   * Get benchmark status
   * @returns {Promise<object>} Benchmark availability status
   */
  getStatus: async () => {
    const response = await api.get('/benchmark/status');
    return response.data;
  },

  /**
   * Run benchmark comparison
   * @param {number} iterations - Number of iterations per test
   * @returns {Promise<object>} Benchmark results
   */
  runBenchmark: async (iterations = 10) => {
    const response = await api.post('/benchmark/run', { iterations });
    return response.data;
  }
};

// ============================================
// PQC Session APIs
// ============================================
export const pqcAPI = {
  /**
   * Initialize PQC session with server
   * @param {string} username - Username
   * @param {string} userId - User ID
   * @returns {Promise<object>} Session data with server public key
   */
  initSession: async (username, userId) => {
    const response = await api.post('/auth/pqc/init', {
      username,
      userId
    });
    return response.data;
  },

  /**
   * Confirm PQC session with client's public key
   * @param {string} sessionId - Session ID
   * @param {object} clientKeyData - Client's public key data
   * @returns {Promise<object>} Confirmation response
   */
  confirmPQCSession: async (sessionId, clientKeyData) => {
    const response = await api.post('/auth/pqc/confirm', {
      session_id: sessionId,
      client_public_key: clientKeyData.client_public_key
    });
    return response.data;
  },

  /**
   * Get PQC session status
   * @returns {Promise<object>} Session status
   */
  getStatus: async () => {
    const response = await api.get('/pqc/session/status');
    return response.data;
  },

  /**
   * Send heartbeat to keep session alive
   * @returns {Promise<object>} Heartbeat response
   */
  heartbeat: async () => {
    const response = await api.post('/pqc/session/heartbeat');
    return response.data;
  },

  /**
   * Close PQC session
   * @returns {Promise<object>} Logout response
   */
  logout: async () => {
    const response = await api.post('/pqc/session/logout');
    return response.data;
  },

  /**
   * List all active sessions
   * @returns {Promise<object>} List of sessions
   */
  listSessions: async () => {
    const response = await api.get('/pqc/session/sessions');
    return response.data;
  }
};

// ============================================
// Health Check
// ============================================
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export default api;
