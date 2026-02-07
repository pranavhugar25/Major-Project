/**
 * API service for communicating with the backend
 * All requests go through PQC secure channel
 */
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  timeout: 10000
});

// Request interceptor for adding auth tokens (future enhancement)
api.interceptors.request.use(
  (config) => {
    // Future: Add JWT token or session ID here
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor for error handling
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response) {
      // Server responded with error status
      console.error('API Error:', error.response.data);
    } else if (error.request) {
      // Request made but no response
      console.error('Network Error:', error.request);
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

/**
 * Authentication APIs
 */
export const authAPI = {
  /**
   * Register a new user
   * @param {string} username - Username
   * @param {string} masterPassword - Master password
   * @returns {Promise} Response with userId and salt
   */
  register: async (username, masterPassword) => {
    const response = await api.post('/auth/register', {
      username,
      masterPassword
    });
    return response.data;
  },

  /**
   * Login user
   * @param {string} username - Username
   * @param {string} masterPassword - Master password
   * @returns {Promise} Response with userId and salt
   */
  login: async (username, masterPassword) => {
    const response = await api.post('/auth/login', {
      username,
      masterPassword
    });
    return response.data;
  },

  /**
   * Check if username is available
   * @param {string} username - Username to check
   * @returns {Promise} Response with availability status
   */
  checkUsername: async (username) => {
    const response = await api.post('/auth/check-username', {
      username
    });
    return response.data;
  },

  /**
   * Get salt for a username
   * @param {string} username - Username
   * @returns {Promise} Response with salt
   */
  getSalt: async (username) => {
    const response = await api.post('/auth/get-salt', {
      username
    });
    return response.data;
  }
};

/**
 * Password Management APIs
 */
export const passwordAPI = {
  /**
   * Add or update encrypted password
   * @param {object} passwordData - Encrypted password data
   * @returns {Promise} Response with success status
   */
  addPassword: async (passwordData) => {
    const response = await api.post('/passwords/add', passwordData);
    return response.data;
  },

  /**
   * Get all passwords for a user
   * @param {string} userId - User ID
   * @returns {Promise} Response with array of encrypted passwords
   */
  getAllPasswords: async (userId) => {
    const response = await api.post('/passwords/get-all', {
      userId
    });
    return response.data;
  },

  /**
   * Delete a password
   * @param {string} passwordId - Password ID to delete
   * @returns {Promise} Response with success status
   */
  deletePassword: async (passwordId) => {
    const response = await api.post('/passwords/delete', {
      passwordId
    });
    return response.data;
  },

  /**
   * Get crypto view (for transparency)
   * @param {string} userId - User ID
   * @returns {Promise} Response with encrypted data view
   */
  getCryptoView: async (userId) => {
    const response = await api.post('/passwords/get-crypto-view', {
      userId
    });
    return response.data;
  }
};

/**
 * Health check
 */
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

export default api;
