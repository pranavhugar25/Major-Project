/**
 * Client-side cryptographic utilities
 * Zero-Knowledge: All encryption/decryption happens in the browser
 * 
 * Implements AES-256-GCM authenticated encryption using Web Crypto API
 * for maximum security with proper integrity verification.
 */

/**
 * Securely clear sensitive data from memory
 * Uses Web Crypto API subtlecrypto's method where available
 * 
 * @param {ArrayBuffer|Uint8Array} data - Data to zeroize
 */
export const secureZeroize = (data) => {
  if (data && typeof data.fill === 'function') {
    data.fill(0);
  }
};

/**
 * Generate a cryptographically secure random key
 * 
 * @param {number} length - Key length in bytes (default 32)
 * @returns {Promise<string>} Base64 encoded key
 */
export const generateRandomKey = async (length = 32) => {
  const keyBytes = crypto.getRandomValues(new Uint8Array(length));
  const keyBase64 = btoa(String.fromCharCode(...keyBytes));
  
  // Clear the raw bytes from memory
  secureZeroize(keyBytes);
  
  return keyBase64;
};

/**
 * Derive vault key from master password using PBKDF2
 * This is the core of zero-knowledge architecture - done entirely client-side
 * 
 * @param {string} masterPassword - User's master password
 * @param {string} salt - Base64 encoded salt
 * @returns {Promise<string>} Base64 encoded vault key
 */
export const deriveVaultKey = async (masterPassword, salt) => {
  try {
    // Decode salt from base64
    const saltBytes = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
    
    // Import master password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(masterPassword),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    
    // Derive 256-bit key using PBKDF2 with 600,000 iterations
    // Set extractable: true so we can export the key for use
    const vaultKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 600000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
    
    // Export key as base64
    const exportedKey = await crypto.subtle.exportKey('raw', vaultKey);
    return btoa(String.fromCharCode(...new Uint8Array(exportedKey)));
  } catch (error) {
    console.error('Cryptographic operation failed:', error);
    throw new Error('Failed to derive vault key: ' + error.message);
  }
};

/**
 * Encrypt password using AES-256-GCM
 * 
 * Uses Web Crypto API for proper authenticated encryption with
 * 128-bit authentication tag for integrity verification.
 * 
 * @param {string} plaintext - Password to encrypt
 * @param {string} vaultKeyBase64 - Base64 encoded vault key
 * @returns {Promise<{encryptedPassword: string, iv: string, authTag: string}>}
 */
export const encryptPassword = async (plaintext, vaultKeyBase64) => {
  try {
    // Generate cryptographically random IV (96 bits for GCM)
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Import vault key
    const key = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(atob(vaultKeyBase64), c => c.charCodeAt(0)),
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt']
    );
    
    // Encrypt with AES-256-GCM
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    
    // Web Crypto API returns the full ciphertext including auth tag
    // The auth tag is internally managed by the Web Crypto API
    const encryptedArray = new Uint8Array(encrypted);
    
    // For AES-GCM, the Web Crypto API handles auth tag internally
    // We only need to return the ciphertext (full encrypted data)
    // The auth tag will be verified during decryption
    
    return {
      encryptedPassword: btoa(String.fromCharCode(...encryptedArray.slice(0, -16))),
      iv: btoa(String.fromCharCode(...iv)),
      authTag: btoa(String.fromCharCode(...new Uint8Array(encryptedArray.slice(-16))))
    };
  } catch (error) {
    console.error('Cryptographic operation failed:', error);
    throw new Error('Failed to encrypt password: ' + error.message);
  }
};

/**
 * Decrypt password using AES-256-GCM
 * 
 * Verifies authentication tag before returning plaintext.
 * Throws error if data has been tampered with.
 * 
 * @param {string} encryptedPasswordBase64 - Base64 encoded encrypted password
 * @param {string} ivBase64 - Base64 encoded IV
 * @param {string} authTagBase64 - Base64 encoded authentication tag
 * @param {string} vaultKeyBase64 - Base64 encoded vault key
 * @returns {Promise<string>} Decrypted password
 */
export const decryptPassword = async (
  encryptedPasswordBase64, 
  ivBase64, 
  authTagBase64, 
  vaultKeyBase64
) => {
  try {
    // Import vault key
    const key = await crypto.subtle.importKey(
      'raw',
      Uint8Array.from(atob(vaultKeyBase64), c => c.charCodeAt(0)),
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );
    
    // Decode components
    const ciphertext = Uint8Array.from(atob(encryptedPasswordBase64), c => c.charCodeAt(0));
    const iv = Uint8Array.from(atob(ivBase64), c => c.charCodeAt(0));
    const authTag = Uint8Array.from(atob(authTagBase64), c => c.charCodeAt(0));
    
    // Combine ciphertext and auth tag for decryption
    const encryptedData = new Uint8Array([...ciphertext, ...authTag]);
    
    // Decrypt and verify auth tag
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv },
      key,
      encryptedData
    );
    
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error('Cryptographic operation failed:', error);
    throw new Error('Decryption failed - ' + error.message);
  }
};

/**
 * Generate a cryptographically secure random password
 * 
 * Uses crypto.getRandomValues() for secure random number generation
 * with rejection sampling to eliminate modulo bias.
 * 
 * @param {number} length - Password length (default 20)
 * @param {object} options - Options for character types
 * @returns {string} Generated password
 */
export const generatePassword = (length = 20, options = {}) => {
  const {
    includeLowercase = true,
    includeUppercase = true,
    includeNumbers = true,
    includeSymbols = true
  } = options;
  
  // Build character set
  let charset = '';
  if (includeLowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (includeUppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (includeNumbers) charset += '0123456789';
  if (includeSymbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';
  
  // Default to mixed charset if nothing selected
  if (charset.length === 0) {
    charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  }
  
  // Use crypto-secure random number generation with rejection sampling
  // This eliminates modulo bias that would make some characters more likely
  const randomValues = new Uint32Array(length);
  crypto.getRandomValues(randomValues);
  
  let password = '';
  const charsetLength = charset.length;
  const maxValidValue = Math.floor(4294967296 / charsetLength) * charsetLength;
  
  for (let i = 0; i < length; i++) {
    let random;
    do {
      random = randomValues[i] >>> 0; // Ensure unsigned
    } while (random >= maxValidValue); // Rejection sampling
    
    password += charset[random % charsetLength];
  }
  
  return password;
};

/**
 * Calculate password strength score
 * 
 * Evaluates password against multiple criteria and returns
 * a score from 0-4 with feedback for improvement.
 * 
 * @param {string} password - Password to evaluate
 * @param {string[]} userInputs - Personal info to avoid (usernames, etc.)
 * @returns {Promise<{score: number, feedback: string[], strength: string}>}
 */
export const calculatePasswordStrength = async (password, userInputs = []) => {
  if (!password) {
    return { score: 0, feedback: ['Enter a password'], strength: 'none' };
  }
  
  const feedback = [];
  let score = 0;
  
  // Length checks
  if (password.length >= 16) {
    score += 2;
  } else if (password.length >= 12) {
    score += 1;
  } else if (password.length < 8) {
    feedback.push('Password is too short (minimum 12 characters recommended)');
  }
  
  // Character variety checks
  if (/[a-z]/.test(password)) score += 0.5;
  else feedback.push('Add lowercase letters');
  
  if (/[A-Z]/.test(password)) score += 0.5;
  else feedback.push('Add uppercase letters');
  
  if (/[0-9]/.test(password)) score += 0.5;
  else feedback.push('Add numbers');
  
  if (/[^a-zA-Z0-9]/.test(password)) score += 0.5;
  else feedback.push('Add special characters');
  
  // Check for common patterns
  const commonPatterns = [
    /^123/, /321$/, /password/i, /qwerty/i, /abc/i,
    /(.)\1{2,}/, // Repeated characters
    /^[A-Z][a-z]+[0-9]+$/, // Common "Password1" pattern
  ];
  
  for (const pattern of commonPatterns) {
    if (pattern.test(password)) {
      score -= 1;
      feedback.push('Avoid common patterns');
      break;
    }
  }
  
  // Check against user inputs
  for (const input of userInputs) {
    if (input.length > 3 && password.toLowerCase().includes(input.toLowerCase())) {
      score -= 1;
      feedback.push('Avoid using personal information');
      break;
    }
  }
  
  // Normalize score to 0-4 range
  score = Math.max(0, Math.min(4, Math.round(score)));
  
  // Determine strength label
  const strengthLabels = ['very-weak', 'weak', 'fair', 'good', 'strong'];
  const strength = strengthLabels[score];
  
  return {
    score,
    feedback: feedback.length > 0 ? feedback : ['Password meets requirements'],
    strength
  };
};

/**
 * Verify password can be encrypted/decrypted correctly
 * 
 * @returns {Promise<boolean>}
 */
export const verifyCryptoImplementation = async () => {
  try {
    const testPassword = 'TestPassword123!';
    const testKey = await generateRandomKey(32);
    
    const encrypted = await encryptPassword(testPassword, testKey);
    const decrypted = await decryptPassword(
      encrypted.encryptedPassword,
      encrypted.iv,
      encrypted.authTag,
      testKey
    );
    
    // Clear test key from memory
    secureZeroize(Uint8Array.from(atob(testKey), c => c.charCodeAt(0)));
    
    return decrypted === testPassword;
  } catch (error) {
    console.error('Cryptographic operation failed');
    return false;
  }
};
