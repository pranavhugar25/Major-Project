/**
 * API service for communicating with the backend
 * JWT-based authentication with automatic token management
 * 
 * SECURITY RECOMMENDATIONS FOR PRODUCTION:
 * 
 * 1. Use httpOnly, Secure, SameSite=Strict cookies for tokens
 * 2. Implement CSRF protection with CSRF tokens
 * 3. Add Content-Security-Policy headers
 * 4. Implement token rotation
 * 5. Use shorter access token lifetimes (5-15 minutes)
 * 6. Consider using Refresh Token Rotation
 * 
 * Current implementation uses sessionStorage which is vulnerable to XSS attacks.
 * For production, implement httpOnly cookies on the backend.
 */
import axios from 'axios';
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';
const MAIN_AUTH_PROTOCOL = process.env.REACT_APP_AUTH_PROTOCOL || 'split-verifier';
const MAIN_TRANSPORT_PROTOCOL = process.env.REACT_APP_TRANSPORT_PROTOCOL || 'hybrid_pqc';

// Token storage keys
const ACCESS_TOKEN_KEY = 'pqc_access_token';
const REFRESH_TOKEN_KEY = 'pqc_refresh_token';
const TOKEN_EXPIRY_KEY = 'pqc_token_expiry';
const CSRF_TOKEN_KEY = 'pqc_csrf_token';
const TRANSPORT_KDF_CONTEXTS = {
  hybrid_pqc: 'pqc-hybrid-transport-v1',
  classical_ecdh: 'classical-ecdh-transport-v1'
};
const TRANSPORT_SESSION_SKEW_MS = 15000;

let transportSession = null;

// Create axios instance with default config
const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json'
  },
  timeout: 10000
});

const bytesToBase64 = (bytes) => {
  const chunkSize = 0x8000;
  let binary = '';
  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunkSize));
  }
  return btoa(binary);
};

const base64ToBytes = (value) => Uint8Array.from(atob(value), (char) => char.charCodeAt(0));

const concatBytes = (...parts) => {
  const totalLength = parts.reduce((sum, part) => sum + part.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const clearTransportSession = () => {
  transportSession = null;
};

const deriveTransportKey = async ({ protocol, pqcSecretBytes, ecdhSecretBytes }) => {
  const contextLabel = TRANSPORT_KDF_CONTEXTS[protocol];
  if (!contextLabel) {
    throw new Error(`Unsupported transport protocol: ${protocol}`);
  }
  const contextBytes = new TextEncoder().encode(contextLabel);
  const input = protocol === 'hybrid_pqc'
    ? concatBytes(pqcSecretBytes, ecdhSecretBytes)
    : concatBytes(ecdhSecretBytes);
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    input,
    'HKDF',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array([]),
      info: contextBytes
    },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
};

const encryptTransportPayload = async (payload, transportKeyBytes) => {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    transportKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    plaintext
  );
  return {
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  };
};

const decryptTransportPayload = async (transportEnvelope, transportKeyBytes) => {
  const iv = base64ToBytes(transportEnvelope.iv || '');
  const ciphertext = base64ToBytes(transportEnvelope.ciphertext || '');
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    transportKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    cryptoKey,
    ciphertext
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
};

const ensureTransportSession = async () => {
  if (transportSession && Date.now() < (transportSession.expiresAt - TRANSPORT_SESSION_SKEW_MS)) {
    return transportSession;
  }

  const clientEcdhKeys = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const clientEcdhPublicRaw = new Uint8Array(
    await crypto.subtle.exportKey('raw', clientEcdhKeys.publicKey)
  );

  const requestBody = {
    protocol: MAIN_TRANSPORT_PROTOCOL,
    clientEcdhPublicKey: bytesToBase64(clientEcdhPublicRaw)
  };
  let clientPqcKeyPair = null;
  if (MAIN_TRANSPORT_PROTOCOL === 'hybrid_pqc') {
    clientPqcKeyPair = ml_kem1024.keygen();
    requestBody.clientPqcPublicKey = bytesToBase64(clientPqcKeyPair.publicKey);
  }

  const response = await api.post('/transport/init', requestBody);

  if (!response.data?.success) {
    throw new Error(response.data?.error || 'Failed to initialize hybrid transport session');
  }

  if (response.data?.protocol !== MAIN_TRANSPORT_PROTOCOL) {
    throw new Error(
      `Transport protocol mismatch. Expected ${MAIN_TRANSPORT_PROTOCOL}, got ${response.data?.protocol || 'unknown'}`
    );
  }

  const serverEcdhPublicRaw = base64ToBytes(response.data.serverEcdhPublicKey || '');
  let pqcSharedSecret = new Uint8Array([]);
  if (MAIN_TRANSPORT_PROTOCOL === 'hybrid_pqc') {
    const pqcCiphertext = base64ToBytes(response.data.pqcCiphertext || '');
    pqcSharedSecret = ml_kem1024.decapsulate(pqcCiphertext, clientPqcKeyPair.secretKey);
  }

  const serverEcdhPublicKey = await crypto.subtle.importKey(
    'raw',
    serverEcdhPublicRaw,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  const ecdhBits = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: 'ECDH', public: serverEcdhPublicKey },
      clientEcdhKeys.privateKey,
      256
    )
  );

  const transportKey = await deriveTransportKey({
    protocol: MAIN_TRANSPORT_PROTOCOL,
    pqcSecretBytes: new Uint8Array(pqcSharedSecret),
    ecdhSecretBytes: ecdhBits
  });
  transportSession = {
    sessionId: response.data.sessionId,
    protocol: MAIN_TRANSPORT_PROTOCOL,
    transportKeyBytes: transportKey,
    expiresAt: Date.now() + ((response.data.expiresIn || 900) * 1000)
  };
  return transportSession;
};

const securePost = async (url, payload) => {
  const execute = async () => {
    const session = await ensureTransportSession();
    const encryptedPayload = await encryptTransportPayload(payload, session.transportKeyBytes);
    const response = await api.post(url, {
      transport: {
        sessionId: session.sessionId,
        iv: encryptedPayload.iv,
        ciphertext: encryptedPayload.ciphertext
      }
    });

    if (response.data?.transport) {
      return await decryptTransportPayload(response.data.transport, session.transportKeyBytes);
    }
    return response.data;
  };

  try {
    return await execute();
  } catch (error) {
    const message = String(error?.response?.data?.error || '').toLowerCase();
    const shouldRetry = message.includes('transport session') || message.includes('transport payload');
    if (shouldRetry) {
      clearTransportSession();
      return await execute();
    }
    throw error;
  }
};

// ============================================
// Request Interceptor - Add JWT Token
// ============================================
api.interceptors.request.use(
  (config) => {
    const token = sessionStorage.getItem(ACCESS_TOKEN_KEY);
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    const method = (config.method || 'GET').toUpperCase();
    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      const csrfToken = sessionStorage.getItem(CSRF_TOKEN_KEY);
      if (csrfToken) {
        config.headers['X-CSRF-Token'] = csrfToken;
      }
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
    
    // Handle 401 errors or token expiration - attempt token refresh
    if (
      (error.response?.status === 401 || isTokenExpired()) &&
      !originalRequest._retry &&
      !String(originalRequest?.url || '').includes('/auth/refresh')
    ) {
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
 * 
 * SECURITY NOTE: For production, use httpOnly cookies instead of sessionStorage
 * to prevent XSS token theft. This requires backend cookie handling support.
 * 
 * Current implementation uses sessionStorage for:
 * - Persistence across page refreshes within same tab
 * - Accessibility for token refresh operations
 * 
 * Risks: XSS attacks can steal tokens from sessionStorage
 * Mitigation: Implement httpOnly cookies on backend
 * 
 * @param {object} tokenData - Object containing access_token, refresh_token, expires_in
 */
export const setAuthTokens = (tokenData) => {
  if (tokenData.access_token) {
    sessionStorage.setItem(ACCESS_TOKEN_KEY, tokenData.access_token);
    // Store expiration time (default: 15 minutes)
    const expiresIn = tokenData.expires_in || 900; // 15 minutes in seconds
    const expiryTime = Date.now() + (expiresIn * 1000);
    sessionStorage.setItem(TOKEN_EXPIRY_KEY, expiryTime.toString());
  }
  if (tokenData.refresh_token) {
    sessionStorage.setItem(REFRESH_TOKEN_KEY, tokenData.refresh_token);
  }
  if (tokenData.csrf_token) {
    sessionStorage.setItem(CSRF_TOKEN_KEY, tokenData.csrf_token);
  }
};

/**
 * Clear authentication tokens
 */
export const clearAuthTokens = () => {
  sessionStorage.removeItem(ACCESS_TOKEN_KEY);
  sessionStorage.removeItem(REFRESH_TOKEN_KEY);
  sessionStorage.removeItem(TOKEN_EXPIRY_KEY);
  sessionStorage.removeItem(CSRF_TOKEN_KEY);
  clearTransportSession();
};

/**
 * Check if access token is expired
 * @returns {boolean} True if token is expired or no token exists
 */
export const isTokenExpired = () => {
  const expiryStr = sessionStorage.getItem(TOKEN_EXPIRY_KEY);
  if (!expiryStr) return true;
  const expiryTime = parseInt(expiryStr, 10);
  return Date.now() >= expiryTime;
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
  return !!getAccessToken() && !isTokenExpired();
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
  clearTransportSession();
  // Store tokens
  setAuthTokens({
    access_token: loginData.access_token,
    refresh_token: loginData.refresh_token,
    csrf_token: loginData.csrf_token,
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
   * @param {string} salt - Base64 encoded registration salt
   * @param {string} passwordVerifier - Base64 PBKDF2 verifier (never plaintext password)
   * @returns {Promise<object>} Response with userId and salt
   */
  register: async (username, salt, passwordVerifier) => {
    const response = await api.post('/auth/register', {
      username,
      salt,
      passwordVerifier,
      authProtocol: MAIN_AUTH_PROTOCOL
    });
    return response.data;
  },

  /**
   * Request a one-time login challenge.
   * @param {string} username - Username
   * @returns {Promise<object>} Response with challengeId, challenge, and salt
   */
  getLoginChallenge: async (username) => {
    const response = await api.post('/auth/login/challenge', {
      username,
      authProtocol: MAIN_AUTH_PROTOCOL
    });
    return response.data;
  },

  /**
   * Login user using challenge-response proof - returns JWT tokens
   * @param {string} username - Username
   * @param {string} challengeId - One-time challenge ID
   * @param {string} challengeResponse - HMAC proof derived from auth verifier
   * @returns {Promise<object>} Response with tokens, userId, and salt
   */
  login: async (username, challengeId, challengeResponse) => {
    const response = await api.post('/auth/login', {
      username,
      challengeId,
      challengeResponse,
      authProtocol: MAIN_AUTH_PROTOCOL
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
    if (response.data?.success) {
      setAuthTokens(response.data);
    }
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
      const refreshToken = sessionStorage.getItem(REFRESH_TOKEN_KEY);
      await api.post('/auth/logout', {
        refresh_token: refreshToken || undefined
      });
    } finally {
      handleLogout();
    }
  }
};

// ============================================
// Benchmark APIs
// ============================================
export const benchmarkAPI = {
  getProtocols: async () => {
    const response = await api.get('/benchmark/protocols');
    return response.data;
  },

  run: async ({ iterations = 3, payloadSize = 1024 } = {}) => {
    const response = await api.post('/benchmark/run', {
      iterations,
      payloadSize
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
    return securePost('/passwords/add', passwordData);
  },

  /**
   * Get all passwords for authenticated user
   * @returns {Promise<object>} Array of encrypted passwords
   */
  getAllPasswords: async () => {
    return securePost('/passwords/get-all', {});
  },

  /**
   * Delete a password
   * @param {string} passwordId - Password ID to delete
   * @returns {Promise<object>} Success status
   */
  deletePassword: async (passwordId) => {
    return securePost('/passwords/delete', { passwordId });
  },

  /**
   * Get crypto view (for transparency)
   * @returns {Promise<object>} Encrypted data view
   */
  getCryptoView: async () => {
    return securePost('/passwords/get-crypto-view', {});
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
