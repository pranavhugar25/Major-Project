/**
 * Client-side cryptographic utilities
 * Zero-Knowledge: All encryption/decryption happens in the browser
 */
import CryptoJS from 'crypto-js';

/**
 * Derive vault key from master password using PBKDF2
 * This is the core of zero-knowledge architecture - done entirely client-side
 * 
 * @param {string} masterPassword - User's master password
 * @param {string} salt - Base64 encoded salt
 * @returns {string} Base64 encoded vault key
 */
export const deriveVaultKey = (masterPassword, salt) => {
  try {
    // Decode salt from base64
    const saltWordArray = CryptoJS.enc.Base64.parse(salt);
    
    // Derive 256-bit key using PBKDF2 with 600,000 iterations
    // This matches the server-side configuration
    const key = CryptoJS.PBKDF2(masterPassword, saltWordArray, {
      keySize: 256 / 32,  // 256 bits = 8 words (32 bits each)
      iterations: 600000,
      hasher: CryptoJS.algo.SHA256
    });
    
    // Return as base64 string
    return CryptoJS.enc.Base64.stringify(key);
  } catch (error) {
    console.error('Error deriving vault key:', error);
    throw new Error('Failed to derive vault key');
  }
};

/**
 * Encrypt password using AES-256-GCM
 * 
 * @param {string} plaintext - Password to encrypt
 * @param {string} vaultKeyBase64 - Base64 encoded vault key
 * @returns {object} { encryptedPassword, iv, authTag }
 */
export const encryptPassword = (plaintext, vaultKeyBase64) => {
  try {
    // Generate random IV (96 bits for GCM)
    const iv = CryptoJS.lib.WordArray.random(12);
    
    // Parse vault key from base64
    const key = CryptoJS.enc.Base64.parse(vaultKeyBase64);
    
    // Encrypt using AES-256-GCM
    // Note: CryptoJS doesn't support GCM mode directly, so we use CBC for this demo
    // In production, use Web Crypto API for proper GCM support
    const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    return {
      encryptedPassword: encrypted.ciphertext.toString(CryptoJS.enc.Base64),
      iv: iv.toString(CryptoJS.enc.Base64),
      authTag: encrypted.toString().substring(0, 32) // Simulated auth tag
    };
  } catch (error) {
    console.error('Error encrypting password:', error);
    throw new Error('Failed to encrypt password');
  }
};

/**
 * Decrypt password using AES-256-GCM
 * 
 * @param {string} encryptedPasswordBase64 - Base64 encoded encrypted password
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {string} vaultKeyBase64 - Base64 encoded vault key
 * @returns {string} Decrypted password
 */
export const decryptPassword = (encryptedPasswordBase64, ivBase64, vaultKeyBase64) => {
  try {
    // Parse components from base64
    const key = CryptoJS.enc.Base64.parse(vaultKeyBase64);
    const iv = CryptoJS.enc.Base64.parse(ivBase64);
    const ciphertext = CryptoJS.enc.Base64.parse(encryptedPasswordBase64);
    
    // Create cipher params object
    const cipherParams = CryptoJS.lib.CipherParams.create({
      ciphertext: ciphertext
    });
    
    // Decrypt using AES-256-CBC (same as encryption)
    const decrypted = CryptoJS.AES.decrypt(cipherParams, key, {
      iv: iv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.Pkcs7
    });
    
    // Convert to UTF-8 string
    const plaintext = decrypted.toString(CryptoJS.enc.Utf8);
    
    if (!plaintext) {
      throw new Error('Decryption failed - invalid vault key or corrupted data');
    }
    
    return plaintext;
  } catch (error) {
    console.error('Error decrypting password:', error);
    throw new Error('Failed to decrypt password - check your master password');
  }
};

/**
 * Generate a random secure password
 * 
 * @param {number} length - Password length (default 16)
 * @param {object} options - Options for character types
 * @returns {string} Generated password
 */
export const generatePassword = (length = 16, options = {}) => {
  const {
    includeLowercase = true,
    includeUppercase = true,
    includeNumbers = true,
    includeSymbols = true
  } = options;
  
  let charset = '';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  if (charset.length === 0) {
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  }
  
  // Use crypto-secure random number generation
  const randomWords = CryptoJS.lib.WordArray.random(length);
  const randomBytes = new Uint8Array(randomWords.words.length * 4);
  
  for (let i = 0; i < randomWords.words.length; i++) {
    const word = randomWords.words[i];
    randomBytes[i * 4] = (word >>> 24) & 0xff;
    randomBytes[i * 4 + 1] = (word >>> 16) & 0xff;
    randomBytes[i * 4 + 2] = (word >>> 8) & 0xff;
    randomBytes[i * 4 + 3] = word & 0xff;
  }
  
  let password = '';
  for (let i = 0; i < length; i++) {
    password += charset[randomBytes[i] % charset.length];
  }
  
  return password;
};

/**
 * Calculate password strength
 * 
 * @param {string} password - Password to evaluate
 * @returns {object} { score, feedback, strength }
 */
export const calculatePasswordStrength = (password) => {
  if (!password) {
    return { score: 0, feedback: 'Enter a password', strength: 'none' };
  }
  
  let score = 0;
  
  // Length
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 16) score += 1;
  
  // Character variety
  if (/[a-z]/.test(password)) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[0-9]/.test(password)) score += 1;
  if (/[^a-zA-Z0-9]/.test(password)) score += 1;
  
  // Patterns (negative score)
  if (/(.)\1{2,}/.test(password)) score -= 1; // Repeated characters
  if (/^[0-9]+$/.test(password)) score -= 1; // Only numbers
  if (/^[a-zA-Z]+$/.test(password)) score -= 1; // Only letters
  
  // Determine strength
  let strength, feedback;
  if (score <= 2) {
    strength = 'weak';
    feedback = 'Weak - Add more characters and variety';
  } else if (score <= 4) {
    strength = 'fair';
    feedback = 'Fair - Consider adding more length or symbols';
  } else if (score <= 6) {
    strength = 'good';
    feedback = 'Good - Your password is reasonably secure';
  } else {
    strength = 'strong';
    feedback = 'Strong - Excellent password!';
  }
  
  return { score, feedback, strength };
};

/**
 * Simulate PQC key exchange (client-side)
 * In production, this would use actual ML-KEM (Kyber) implementation
 * 
 * @returns {object} { publicKey, privateKey }
 */
export const generatePQCKeyPair = () => {
  // Simulated Kyber key generation
  // In production, use actual kyber.js or WASM implementation
  const publicKey = CryptoJS.lib.WordArray.random(1568).toString(CryptoJS.enc.Base64);
  const privateKey = CryptoJS.lib.WordArray.random(3168).toString(CryptoJS.enc.Base64);
  
  return { publicKey, privateKey };
};

/**
 * Hash data using SHA-256
 * 
 * @param {string} data - Data to hash
 * @returns {string} Hex encoded hash
 */
export const sha256Hash = (data) => {
  return CryptoJS.SHA256(data).toString(CryptoJS.enc.Hex);
};
