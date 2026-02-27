/**
 * Post-Quantum Cryptography utilities for client-side operations
 * Uses noble-post-quantum library (browser standalone build)
 */

// Noble post-quantum global from browser build
let nobleModule = null;

/**
 * Load noble-post-quantum from global browser build
 */
function loadNoblePQC() {
  if (nobleModule) return nobleModule;
  
  // Check if the global noblePostQuantum is available
  if (typeof window !== 'undefined' && window.noblePostQuantum) {
    nobleModule = window.noblePostQuantum;
    console.log('[PQC] noble-post-quantum loaded from browser build');
    return nobleModule;
  }
  
  console.warn('[PQC] noble-post-quantum not available');
  return null;
}

/**
 * Get ML-KEM instance (NIST Level 5 = ML-KEM-1024)
 */
export function getMLKEM() {
  const pqc = loadNoblePQC();
  if (!pqc) {
    throw new Error('PQC library not loaded');
  }
  return pqc.ml_kem1024;
}

/**
 * Get ML-DSA instance (NIST Level 5 = ML-DSA-87)
 */
export function getMLDSA() {
  const pqc = loadNoblePQC();
  if (!pqc) {
    throw new Error('PQC library not loaded');
  }
  return pqc.ml_dsa87;
}

/**
 * Generate ML-KEM-1024 keypair (NIST Level 5)
 * @param {Uint8Array} seed - Optional seed for deterministic key generation
 * @returns {Object} Keypair with publicKey and secretKey
 */
export async function generateKeypair(seed) {
  const ml_kem = getMLKEM();
  try {
    const keypair = ml_kem.keygen(seed);
    return {
      publicKey: keypair.publicKey,
      secretKey: keypair.secretKey
    };
  } catch (error) {
    console.error('[PQC] Key generation error:', error);
    throw error;
  }
}

/**
 * Encapsulate shared secret using ML-KEM-1024
 * @param {Uint8Array} publicKey - Recipient's public key
 * @returns {Object} Ciphertext and shared secret
 */
export async function encapsulate(publicKey) {
  const ml_kem = getMLKEM();
  try {
    const result = ml_kem.encapsulate(publicKey);
    return {
      cipherText: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  } catch (error) {
    console.error('[PQC] Encapsulation error:', error);
    throw error;
  }
}

/**
 * Decapsulate shared secret using ML-KEM-1024
 * @param {Uint8Array} cipherText - Ciphertext from sender
 * @param {Uint8Array} secretKey - Recipient's secret key
 * @returns {Uint8Array} Shared secret
 */
export async function decapsulate(cipherText, secretKey) {
  const ml_kem = getMLKEM();
  try {
    return ml_kem.decapsulate(cipherText, secretKey);
  } catch (error) {
    console.error('[PQC] Decapsulation error:', error);
    throw error;
  }
}

/**
 * Sign data using ML-DSA-87 (NIST Level 5)
 * @param {Uint8Array} message - Message to sign
 * @param {Uint8Array} secretKey - Signer's secret key
 * @returns {Uint8Array} Signature
 */
export async function sign(message, secretKey) {
  const ml_dsa = getMLDSA();
  try {
    return ml_dsa.sign(message, secretKey);
  } catch (error) {
    console.error('[PQC] Signing error:', error);
    throw error;
  }
}

/**
 * Verify signature using ML-DSA-87
 * @param {Uint8Array} signature - Signature to verify
 * @param {Uint8Array} message - Original message
 * @param {Uint8Array} publicKey - Signer's public key
 * @returns {boolean} True if signature is valid
 */
export async function verify(signature, message, publicKey) {
  const ml_dsa = getMLDSA();
  try {
    return ml_dsa.verify(signature, message, publicKey);
  } catch (error) {
    console.error('[PQC] Verification error:', error);
    throw error;
  }
}

/**
 * Generate random bytes using crypto.getRandomValues
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
export function getRandomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Check if PQC is available in browser
 * @returns {boolean} True if PQC is available
 */
export function isPQCAvailable() {
  return typeof window !== 'undefined' && !!window.noblePostQuantum;
}

/**
 * Initialize PQC and return status
 * @returns {Object} Status object with availability info
 */
export async function initPQC() {
  const available = isPQCAvailable();
  
  if (available) {
    const ml_kem = getMLKEM();
    const ml_dsa = getMLDSA();
    
    console.log('[PQC] Initialization successful');
    console.log('[PQC] Using ML-KEM-1024 (NIST Level 5)');
    console.log('[PQC] Using ML-DSA-87 (NIST Level 5)');
    
    return {
      available: true,
      ml_kem: 'ML-KEM-1024',
      ml_dsa: 'ML-DSA-87',
      securityLevel: 'NIST Level 5'
    };
  }
  
  return {
    available: false,
    error: 'noble-post-quantum not loaded'
  };
}

/**
 * Initialize PQC session with the server
 * Uses ML-KEM-1024 for key exchange with the server
 * @param {string} username - User's username
 * @param {string} userId - User's ID
 * @returns {Object} Session object
 */
export async function initSession(username, userId) {
  const pqc = loadNoblePQC();
  if (!pqc) {
    throw new Error('PQC library not loaded');
  }
  
  try {
    // Generate ML-KEM-1024 keypair client-side
    const keypair = await generateKeypair();
    
    // Import the API
    const { pqcAPI } = await import('../utils/api');
    
    // Send public key to server to initialize session
    const response = await pqcAPI.initSession({
      userId,
      publicKey: Array.from(keypair.publicKey)
    });
    
    // Decode the server's base64 public key (handle both standard and URL-safe base64)
    // Backend returns server_public_key (snake_case)
    let base64Key = response.server_public_key;
    // Replace URL-safe characters with standard base64 characters
    base64Key = base64Key.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if needed
    while (base64Key.length % 4 !== 0) {
      base64Key += '=';
    }
    const serverPublicKeyBytes = atob(base64Key);
    const serverPublicKey = new Uint8Array(serverPublicKeyBytes.length);
    for (let i = 0; i < serverPublicKeyBytes.length; i++) {
      serverPublicKey[i] = serverPublicKeyBytes.charCodeAt(i);
    }
    
    // Encapsulate to get shared secret
    const sharedSecret = await encapsulate(serverPublicKey);
    
    // Store session info
    const session = {
      session_id: response.sessionId,
      userId,
      publicKey: keypair.publicKey,
      secretKey: keypair.secretKey,
      sharedSecret: sharedSecret.sharedSecret
    };
    
    // Store in sessionStorage
    sessionStorage.setItem('pqc_session', JSON.stringify({
      sessionId: session.session_id,
      publicKey: Array.from(session.publicKey)
    }));
    
    console.log('[PQC] Session initialized successfully with ML-KEM-1024');
    return session;
  } catch (error) {
    console.error('[PQC] Session initialization error:', error);
    throw error;
  }
}

/**
 * Check if there's an active PQC session
 * @returns {boolean} True if there's an active session
 */

