/**
 * Frontend PQC Utilities - Pure Browser-Based Post-Quantum Cryptography
 * 
 * Uses liboqs WASM for all PQC operations in the browser.
 * No backend fallbacks - requires liboqs WASM to be available.
 * 
 * Supported Algorithms:
 * - ML-KEM-1024 (Kyber) for key encapsulation
 * - ML-DSA-87 (Dilithium) for digital signatures
 * 
 * Setup:
 * 1. npm install liboqs
 * 2. Ensure WASM files are in public/liboqs/
 * 3. Run the postinstall script to download WASM bindings
 */

import { api } from './api';

// ====================================================================
// Configuration & Constants
// ====================================================================

const PQC_SESSION_KEY = 'pqc_session';
const PQC_ALGORITHM_KEM = 'ML-KEM-1024';
const PQC_ALGORITHM_SIGNATURE = 'ML-DSA-87';

// liboqs WASM global reference
let liboqs = null;
let wasmInitialized = false;
let wasmLoadAttempted = false;

// ====================================================================
// Utility Functions
// ====================================================================

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer|Uint8Array} buffer 
 * @returns {string}
 */
function arrayBufferToBase64(buffer) {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to Uint8Array
 * @param {string} base64 
 * @returns {Uint8Array}
 */
function base64ToUint8Array(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate random bytes using Web Crypto API
 * @param {number} length 
 * @returns {Uint8Array}
 */
function generateRandomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return array;
}

// ====================================================================
// liboqs WASM Loading (Required)
// ====================================================================

/**
 * Load liboqs WASM module
 * This is REQUIRED for PQC operations - will throw if not available
 * @returns {Promise<void>}
 * @throws {Error} If liboqs WASM cannot be loaded
 */
export async function loadLiboqsWasm() {
  if (wasmInitialized) return;
  if (wasmLoadAttempted) {
    throw new Error('liboqs WASM failed to load previously');
  }
  
  wasmLoadAttempted = true;
  
  try {
    // Try npm package first (liboqs)
    const liboqsModule = await import('liboqs');
    liboqs = await liboqsModule.default();
    
    // Verify it's working
    const testKem = new liboqs.KEM(PQC_ALGORITHM_KEM);
    testKem.free();
    
    wasmInitialized = true;
    console.log('[PQC] liboqs WASM initialized successfully');
  } catch (e) {
    console.error('[PQC] FATAL: liboqs WASM not available:', e.message);
    throw new Error(
      `liboqs WASM is required but failed to load: ${e.message}. ` +
      'Please ensure liboqs is installed and WASM files are available.'
    );
  }
}

/**
 * Check if liboqs WASM is initialized
 * @returns {boolean}
 */
export function isWasmLoaded() {
  return wasmInitialized;
}

/**
 * Ensure WASM is loaded before any operation
 * @private
 */
function ensureWasm() {
  if (!wasmInitialized) {
    throw new Error(
      'liboqs WASM not initialized. Call loadLiboqsWasm() first.'
    );
  }
}

// ====================================================================
// Session Storage Management
// ====================================================================

/**
 * Get PQC session from storage
 * @returns {object|null}
 */
export function getStoredSession() {
  try {
    const stored = sessionStorage.getItem(PQC_SESSION_KEY);
    return stored ? JSON.parse(stored) : null;
  } catch (e) {
    console.error('[PQC] Error reading session:', e);
    return null;
  }
}

/**
 * Store PQC session
 * @param {object} session 
 */
function storeSession(session) {
  try {
    // Store session data (not private keys)
    const safeSession = {
      session_id: session.session_id,
      client_public_key: session.client_public_key,
      server_public_key: session.server_public_key,
      shared_secret: session.shared_secret,
      algorithm: session.algorithm,
      expires_at: session.expires_at,
      idle_timeout_minutes: session.idle_timeout_minutes,
      created_at: session.created_at || new Date().toISOString()
    };
    sessionStorage.setItem(PQC_SESSION_KEY, JSON.stringify(safeSession));
  } catch (e) {
    console.error('[PQC] Error storing session:', e);
  }
}

/**
 * Clear PQC session from storage
 */
export function clearStoredSession() {
  sessionStorage.removeItem(PQC_SESSION_KEY);
}

/**
 * Get current session ID
 * @returns {string|null}
 */
export function getSessionId() {
  const session = getStoredSession();
  return session?.session_id || null;
}

// ====================================================================
// PQC Session Management (Backend-assisted for key exchange)
// ====================================================================

/**
 * Initialize PQC session with server
 * Gets server's public key for ML-KEM-1024 encapsulation
 * @param {string} username - Optional username
 * @param {string} userId - Optional user ID
 * @returns {Promise<object>} Session with server public key
 */
export async function initSession(username = null, userId = null) {
  ensureWasm();
  
  try {
    const response = await api.post('/auth/pqc/init', {
      username,
      user_id: userId
    });

    if (!response.data.success) {
      throw new Error(response.data.error || 'Failed to initialize session');
    }

    const session = {
      session_id: response.data.session_id,
      server_public_key: response.data.server_public_key,
      algorithm: response.data.algorithm,
      expires_at: response.data.expires_at,
      idle_timeout_minutes: response.data.idle_timeout_minutes,
      created_at: new Date().toISOString()
    };
    
    storeSession(session);
    console.log('[PQC] Session initialized with server');
    return session;
  } catch (error) {
    console.error('[PQC] Session init error:', error);
    throw error;
  }
}

/**
 * Send heartbeat to keep session alive
 * @param {string} sessionId - Optional session ID
 * @returns {Promise<object>}
 */
export async function sendHeartbeat(sessionId = null) {
  const sid = sessionId || getSessionId();
  if (!sid) {
    throw new Error('No active session');
  }

  try {
    const response = await api.post('/auth/pqc/heartbeat', {
      session_id: sid
    });

    if (!response.data.success) {
      throw new Error(response.data.error || 'Heartbeat failed');
    }

    // Update stored session
    const stored = getStoredSession();
    if (stored) {
      stored.expires_at = response.data.expires_at;
      storeSession(stored);
    }

    return {
      session_id: response.data.session_id,
      last_activity: response.data.last_activity,
      expires_at: response.data.expires_at
    };
  } catch (error) {
    console.error('[PQC] Heartbeat error:', error);
    if (error.response?.status === 404) {
      clearStoredSession();
    }
    throw error;
  }
}

/**
 * Get PQC session status
 * @param {string} sessionId - Optional session ID
 * @returns {Promise<object>}
 */
export async function getSessionStatus(sessionId = null) {
  const sid = sessionId || getSessionId();
  if (!sid) {
    return { active: false, error: 'No session ID' };
  }

  try {
    const response = await api.get('/auth/pqc/status', {
      params: { session_id: sid }
    });

    if (!response.data.success) {
      return { active: false, error: response.data.error };
    }

    return {
      active: response.data.active,
      session_id: response.data.session_id,
      user_id: response.data.user_id,
      created_at: response.data.created_at,
      expires_at: response.data.expires_at,
      last_activity: response.data.last_activity,
      time_remaining_seconds: response.data.time_remaining_seconds,
      idle_timeout_minutes: response.data.idle_timeout_minutes,
      algorithm: response.data.algorithm
    };
  } catch (error) {
    console.error('[PQC] Status error:', error);
    return { active: false, error: error.message };
  }
}

/**
 * Logout and destroy PQC session
 * @param {string} sessionId - Optional session ID
 * @returns {Promise<boolean>}
 */
export async function logoutSession(sessionId = null) {
  const sid = sessionId || getSessionId();
  if (!sid) {
    return true;
  }

  try {
    await api.post('/auth/pqc/logout', {
      session_id: sid
    });
  } catch (error) {
    console.warn('[PQC] Logout warning:', error.message);
  }

  clearStoredSession();
  console.log('[PQC] Session cleared');
  return true;
}

/**
 * Check if session is active
 * @returns {boolean}
 */
export function hasActiveSession() {
  const session = getStoredSession();
  if (!session?.session_id) return false;
  
  if (session.expires_at) {
    const expires = new Date(session.expires_at);
    if (expires < new Date()) {
      clearStoredSession();
      return false;
    }
  }
  
  return true;
}

// ====================================================================
// Key Encapsulation (ML-KEM-1024) - Pure WASM
// ====================================================================

/**
 * Generate ML-KEM-1024 keypair
 * @returns {object} { publicKey, privateKey } - Base64 encoded
 */
export function generateKeypair() {
  ensureWasm();
  
  const kem = new liboqs.KEM(PQC_ALGORITHM_KEM);
  const keyPair = kem.generate_keypair();
  
  const result = {
    publicKey: arrayBufferToBase64(keyPair.public_key),
    privateKey: arrayBufferToBase64(keyPair.secret_key),
    algorithm: PQC_ALGORITHM_KEM
  };
  
  kem.free();
  console.log('[PQC] Generated ML-KEM-1024 keypair');
  return result;
}

/**
 * Encapsulate shared secret using ML-KEM-1024
 * @param {string} publicKey - Base64 encoded public key
 * @returns {object} { ciphertext, sharedSecret } - Base64 encoded
 */
export function encapsulate(publicKey) {
  ensureWasm();
  
  const kem = new liboqs.KEM(PQC_ALGORITHM_KEM);
  const pubKeyBytes = base64ToUint8Array(publicKey);
  
  const result = kem.encapsulate(pubKeyBytes);
  
  const encapsulated = {
    ciphertext: arrayBufferToBase64(result.ciphertext),
    sharedSecret: arrayBufferToBase64(result.shared_secret),
    algorithm: PQC_ALGORITHM_KEM
  };
  
  kem.free();
  console.log('[PQC] Encapsulated shared secret');
  return encapsulated;
}

/**
 * Decapsulate shared secret using ML-KEM-1024
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} privateKey - Base64 encoded private key
 * @returns {string} Base64 encoded shared secret
 */
export function decapsulate(ciphertext, privateKey) {
  ensureWasm();
  
  const kem = new liboqs.KEM(PQC_ALGORITHM_KEM);
  const cipherBytes = base64ToUint8Array(ciphertext);
  const privKeyBytes = base64ToUint8Array(privateKey);
  
  const sharedSecret = kem.decapsulate(cipherBytes, privKeyBytes);
  const result = arrayBufferToBase64(sharedSecret);
  
  kem.free();
  console.log('[PQC] Decapsulated shared secret');
  return result;
}

// ====================================================================
// Digital Signatures (ML-DSA-87) - Pure WASM
// ====================================================================

/**
 * Generate ML-DSA-87 signing keypair
 * @returns {object} { publicKey, privateKey } - Base64 encoded
 */
export function generateSigningKeypair() {
  ensureWasm();
  
  const sig = new liboqs.Signature(PQC_ALGORITHM_SIGNATURE);
  const keyPair = sig.generate_keypair();
  
  const result = {
    publicKey: arrayBufferToBase64(keyPair.public_key),
    privateKey: arrayBufferToBase64(keyPair.secret_key),
    algorithm: PQC_ALGORITHM_SIGNATURE
  };
  
  sig.free();
  console.log('[PQC] Generated ML-DSA-87 signing keypair');
  return result;
}

/**
 * Sign message using ML-DSA-87
 * @param {string} message - Message to sign
 * @param {string} privateKey - Base64 encoded private key
 * @returns {string} Base64 encoded signature
 */
export function sign(message, privateKey) {
  ensureWasm();
  
  const messageBytes = new TextEncoder().encode(message);
  const sig = new liboqs.Signature(PQC_ALGORITHM_SIGNATURE);
  const privKeyBytes = base64ToUint8Array(privateKey);
  
  const signature = sig.sign(messageBytes, privKeyBytes);
  const result = arrayBufferToBase64(signature);
  
  sig.free();
  console.log('[PQC] Signed message with ML-DSA-87');
  return result;
}

/**
 * Verify signature using ML-DSA-87
 * @param {string} message - Original message
 * @param {string} signature - Base64 encoded signature
 * @param {string} publicKey - Base64 encoded public key
 * @returns {boolean}
 */
export function verify(message, signature, publicKey) {
  ensureWasm();
  
  const messageBytes = new TextEncoder().encode(message);
  const sig = new liboqs.Signature(PQC_ALGORITHM_SIGNATURE);
  const pubKeyBytes = base64ToUint8Array(publicKey);
  const sigBytes = base64ToUint8Array(signature);
  
  const isValid = sig.verify(messageBytes, sigBytes, pubKeyBytes);
  
  sig.free();
  console.log('[PQC] Verified ML-DSA-87 signature:', isValid);
  return isValid;
}

// ====================================================================
// High-Level Session Key Exchange
// ====================================================================

/**
 * Establish PQC session with server using ML-KEM-1024
 * This performs a full key exchange:
 * 1. Get server's public key
 * 2. Generate client keypair
 * 3. Encapsulate shared secret
 * 
 * @param {string} username - Optional username
 * @returns {Promise<object>} Session with established shared secret
 */
export async function establishPqcSession(username = null) {
  ensureWasm();
  
  // Step 1: Get server's public key
  const session = await initSession(username);
  
  // Step 2: Generate client keypair
  const clientKeyPair = generateKeypair();
  
  // Step 3: Encapsulate to derive shared secret
  const encapsulation = encapsulate(session.server_public_key);
  
  // Step 4: Store session with all keys
  const storedSession = {
    ...session,
    client_public_key: clientKeyPair.publicKey,
    client_private_key: clientKeyPair.privateKey,
    shared_secret: encapsulation.sharedSecret
  };
  storeSession(storedSession);
  
  return {
    session: storedSession,
    clientPublicKey: clientKeyPair.publicKey,
    sharedSecret: encapsulation.sharedSecret
  };
}

/**
 * Get the established shared secret from session
 * @returns {string|null} Base64 encoded shared secret
 */
export function getSharedSecret() {
  const session = getStoredSession();
  return session?.shared_secret || null;
}

// ====================================================================
// Session Auto-Refresh
// ====================================================================

let heartbeatInterval = null;

/**
 * Start automatic heartbeat
 * @param {number} intervalMs - Interval in ms (default: 60000)
 */
export function startHeartbeat(intervalMs = 60000) {
  stopHeartbeat();
  
  heartbeatInterval = setInterval(async () => {
    if (hasActiveSession()) {
      try {
        await sendHeartbeat();
      } catch (e) {
        console.error('[PQC] Heartbeat error:', e.message);
      }
    } else {
      stopHeartbeat();
    }
  }, intervalMs);
  
  console.log('[PQC] Heartbeat started');
}

/**
 * Stop automatic heartbeat
 */
export function stopHeartbeat() {
  if (heartbeatInterval) {
    clearInterval(heartbeatInterval);
    heartbeatInterval = null;
    console.log('[PQC] Heartbeat stopped');
  }
}

// ====================================================================
// Initialization & Lifecycle
// ====================================================================

/**
 * Initialize PQC utilities
 * MUST be called before any PQC operations
 * @returns {Promise<void>}
 * @throws {Error} If liboqs WASM cannot be loaded
 */
export async function initPqc() {
  console.log('[PQC] Initializing liboqs WASM...');
  
  await loadLiboqsWasm();
  
  if (hasActiveSession()) {
    console.log('[PQC] Resuming existing session');
    startHeartbeat();
  }
  
  console.log('[PQC] Ready for browser-based PQC operations');
}

/**
 * Cleanup PQC utilities
 * Call on logout
 */
export function cleanupPqc() {
  stopHeartbeat();
  logoutSession();
  console.log('[PQC] Cleaned up');
}

// ====================================================================
// Export all functions
// ====================================================================

export default {
  // WASM initialization
  loadLiboqsWasm,
  isWasmLoaded,
  
  // Session management
  initSession,
  sendHeartbeat,
  getSessionStatus,
  logoutSession,
  hasActiveSession,
  getStoredSession,
  getSessionId,
  clearStoredSession,
  
  // Heartbeat
  startHeartbeat,
  stopHeartbeat,
  
  // Key encapsulation (ML-KEM-1024)
  generateKeypair,
  encapsulate,
  decapsulate,
  
  // Digital signatures (ML-DSA-87)
  generateSigningKeypair,
  sign,
  verify,
  
  // High-level
  establishPqcSession,
  getSharedSecret,
  
  // Lifecycle
  initPqc,
  cleanupPqc
};
