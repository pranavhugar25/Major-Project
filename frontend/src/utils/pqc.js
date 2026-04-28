/**
 * Post-Quantum Cryptography utilities for client-side operations
 * Uses noble-post-quantum library (browser standalone build)
 */

// Noble post-quantum global from browser build
let nobleModule = null;
const PQC_LOGGER_PREFIX = '[PQC-FRONTEND]';

/**
 * Load noble-post-quantum from global browser build
 */
function loadNoblePQC() {
  if (nobleModule) {
    console.log(`${PQC_LOGGER_PREFIX} PQC module already loaded`);
    return nobleModule;
  }
  
  // Check if the global noblePostQuantum is available
  if (typeof window !== 'undefined' && window.noblePostQuantum) {
    nobleModule = window.noblePostQuantum;
    console.log(`${PQC_LOGGER_PREFIX} ✓ noble-post-quantum loaded from browser build`);
    console.log(`${PQC_LOGGER_PREFIX} Module location: window.noblePostQuantum`);
    return nobleModule;
  }
  
  console.warn(`${PQC_LOGGER_PREFIX} ✗ noble-post-quantum NOT available - window.noblePostQuantum is undefined`);
  console.warn(`${PQC_LOGGER_PREFIX} Make sure @noble/post-quantum is installed and imported in index.html`);
  return null;
}

/**
 * Get ML-KEM instance (NIST Level 5 = ML-KEM-1024)
 */
export function getMLKEM() {
  const pqc = loadNoblePQC();
  if (!pqc) {
    console.error(`${PQC_LOGGER_PREFIX} getMLKEM() FAILED: PQC library not loaded`);
    throw new Error('PQC library not loaded');
  }
  console.log(`${PQC_LOGGER_PREFIX} ML-KEM-1024 algorithm obtained`);
  return pqc.ml_kem1024;
}

/**
 * Get ML-DSA instance (NIST Level 5 = ML-DSA-87)
 */
export function getMLDSA() {
  const pqc = loadNoblePQC();
  if (!pqc) {
    console.error(`${PQC_LOGGER_PREFIX} getMLDSA() FAILED: PQC library not loaded`);
    throw new Error('PQC library not loaded');
  }
  console.log(`${PQC_LOGGER_PREFIX} ML-DSA-87 algorithm obtained`);
  return pqc.ml_dsa87;
}

/**
 * Generate ML-KEM-1024 keypair (NIST Level 5)
 * @param {Uint8Array} seed - Optional seed for deterministic key generation
 * @returns {Object} Keypair with publicKey and secretKey
 */
export async function generateKeypair(seed) {
  console.log(`${PQC_LOGGER_PREFIX} generateKeypair() called`);
  const ml_kem = getMLKEM();
  try {
    const keypair = ml_kem.keygen(seed);
    console.log(`${PQC_LOGGER_PREFIX} ✓ Keypair generated: pubKey=${keypair.publicKey.length} bytes, secKey=${keypair.secretKey.length} bytes`);
    return {
      publicKey: keypair.publicKey,
      secretKey: keypair.secretKey
    };
  } catch (error) {
    console.error(`${PQC_LOGGER_PREFIX} ✗ Key generation error:`, error);
    throw error;
  }
}

/**
 * Encapsulate shared secret using ML-KEM-1024
 * @param {Uint8Array} publicKey - Recipient's public key
 * @returns {Object} Ciphertext and shared secret
 */
export async function encapsulate(publicKey) {
  console.log(`${PQC_LOGGER_PREFIX} encapsulate() called with publicKey length=${publicKey?.length}`);
  const ml_kem = getMLKEM();
  try {
    const result = ml_kem.encapsulate(publicKey);
    console.log(`${PQC_LOGGER_PREFIX} ✓ Encapsulation successful: ct=${result.cipherText.length} bytes, ss=${result.sharedSecret.length} bytes`);
    return {
      cipherText: result.cipherText,
      sharedSecret: result.sharedSecret
    };
  } catch (error) {
    console.error(`${PQC_LOGGER_PREFIX} ✗ Encapsulation error:`, error);
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
  console.log(`${PQC_LOGGER_PREFIX} decapsulate() called`);
  const ml_kem = getMLKEM();
  try {
    const result = ml_kem.decapsulate(cipherText, secretKey);
    console.log(`${PQC_LOGGER_PREFIX} ✓ Decapsulation successful: secret=${result.length} bytes`);
    return result;
  } catch (error) {
    console.error(`${PQC_LOGGER_PREFIX} ✗ Decapsulation error:`, error);
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
  console.log(`${PQC_LOGGER_PREFIX} sign() called`);
  const ml_dsa = getMLDSA();
  try {
    const signature = ml_dsa.sign(message, secretKey);
    console.log(`${PQC_LOGGER_PREFIX} ✓ Signature generated: ${signature.length} bytes`);
    return signature;
  } catch (error) {
    console.error(`${PQC_LOGGER_PREFIX} ✗ Signing error:`, error);
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
  console.log(`${PQC_LOGGER_PREFIX} verify() called`);
  const ml_dsa = getMLDSA();
  try {
    const result = ml_dsa.verify(signature, message, publicKey);
    console.log(`${PQC_LOGGER_PREFIX} Verification result: ${result ? 'VALID' : 'INVALID'}`);
    return result;
  } catch (error) {
    console.error(`${PQC_LOGGER_PREFIX} ✗ Verification error:`, error);
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
  const available = typeof window !== 'undefined' && !!window.noblePostQuantum;
  console.log(`${PQC_LOGGER_PREFIX} isPQCAvailable(): ${available ? 'YES' : 'NO'}`);
  if (!available) {
    console.warn(`${PQC_LOGGER_PREFIX} window.noblePostQuantum =`, typeof window !== 'undefined' ? window.noblePostQuantum : 'window undefined');
  }
  return available;
}

/**
 * Initialize PQC and return status
 * @returns {Object} Status object with availability info
 */
export async function initPQC() {
  console.log(`${PQC_LOGGER_PREFIX} initPQC() called`);
  const available = isPQCAvailable();
  
  if (available) {
    try {
      const ml_kem = getMLKEM();
      const ml_dsa = getMLDSA();
      
      console.log(`${PQC_LOGGER_PREFIX} ✓ Initialization successful`);
      console.log(`${PQC_LOGGER_PREFIX} ✓ Using ML-KEM-1024 (NIST Level 5)`);
      console.log(`${PQC_LOGGER_PREFIX} ✓ Using ML-DSA-87 (NIST Level 5)`);
      
      return {
        available: true,
        ml_kem: 'ML-KEM-1024',
        ml_dsa: 'ML-DSA-87',
        securityLevel: 'NIST Level 5'
      };
    } catch (error) {
      console.error(`${PQC_LOGGER_PREFIX} ✗ Initialization failed:`, error);
      return {
        available: false,
        error: error.message
      };
    }
  }
  
  console.warn(`${PQC_LOGGER_PREFIX} ✗ PQC not available - noble-post-quantum library not loaded`);
  return {
    available: false,
    error: 'noble-post-quantum not loaded'
  };
}

/**
 * Initialize PQC session with the server
 * @param {string} username - User's username
 * @param {string} userId - User's ID
 * @returns {Promise<object>} Session data including server public key and signature
 */
export async function initSession(username, userId) {
  console.log(`${PQC_LOGGER_PREFIX} initSession() called for user ${username}`);
  const { pqcAPI } = await import('../utils/api');
  const response = await pqcAPI.initSession(username, userId);
  console.log(`${PQC_LOGGER_PREFIX} Session init response received`);
  return response;
}

/**
 * Confirm PQC session with client public key
 * @param {string} sessionId - Session ID
 * @param {object} clientKeyData - Client public key data
 * @returns {Promise<object>} Confirmation response
 */
export async function confirmPQCSession(sessionId, clientKeyData) {
  console.log(`${PQC_LOGGER_PREFIX} confirmPQCSession() called`);
  const { pqcAPI } = await import('../utils/api');
  const response = await pqcAPI.confirmPQCSession(sessionId, clientKeyData);
  return response;
}

/**
 * Check if there's an active PQC session
 * @returns {boolean} True if there's an active session
 */

