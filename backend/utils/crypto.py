"""
Cryptographic utilities for the backend
Handles hashing, PQC key generation, and verification
"""
import hashlib
import secrets
import base64
from typing import Tuple, Optional
import os

# Import real PQC from liboqs
from utils.pqc import PQCKeyManager


def secure_zeroize(data: bytearray) -> None:
    """
    Securely clear sensitive data from memory
    
    Args:
        data: Bytearray to zeroize
    """
    if data:
        for i in range(len(data)):
            data[i] = 0


def generate_salt(length: int = 32) -> str:
    """
    Generate a cryptographically secure random salt
    
    Args:
        length: Length of salt in bytes (default 32)
    
    Returns:
        Base64 encoded salt string
    """
    salt_bytes = secrets.token_bytes(length)
    return base64.b64encode(salt_bytes).decode('utf-8')


def hash_password(password: str, salt: str) -> str:
    """
    Hash password using PBKDF2-HMAC-SHA256
    This is used to verify the master password on the server
    
    Args:
        password: Plain text password
        salt: Base64 encoded salt
    
    Returns:
        Base64 encoded password hash
    """
    salt_bytes = base64.b64decode(salt)
    
    # PBKDF2 with 600,000 iterations (OWASP recommendation for 2024)
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        iterations=600000,
        dklen=32
    )
    
    return base64.b64encode(password_hash).decode('utf-8')


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify password against stored hash
    
    Args:
        password: Plain text password to verify
        salt: Base64 encoded salt
        stored_hash: Base64 encoded stored password hash
    
    Returns:
        True if password matches, False otherwise
    """
    computed_hash = hash_password(password, salt)
    return secrets.compare_digest(computed_hash, stored_hash)


# ============================================================================
# Post-Quantum Cryptography - Real Implementation using liboqs
# ============================================================================
# These functions provide the real PQC operations using ML-KEM-768 and
# ML-DSA-65 from the liboqs library (NIST-standardized).
# 
# See utils/pqc.py for the full implementation.
# ============================================================================

def generate_kyber_keypair() -> Tuple[str, str]:
    """
    Generate ML-KEM-768 key pair for key encapsulation
    
    Returns:
        Tuple of (public_key, private_key) as base64 strings
        
    Note:
        Uses liboqs-python for NIST-standard ML-KEM-768 implementation.
        This provides quantum-resistant key encapsulation.
    """
    return PQCKeyManager.generate_kyber_keypair()


def generate_dilithium_keypair() -> Tuple[str, str]:
    """
    Generate ML-DSA-65 key pair for digital signatures
    
    Returns:
        Tuple of (public_key, private_key) as base64 strings
        
    Note:
        Uses liboqs-python for NIST-standard ML-DSA-65 implementation.
        This provides quantum-resistant digital signatures.
    """
    return PQCKeyManager.generate_dilithium_keypair()


def kyber_encapsulate(public_key: str) -> Tuple[str, str]:
    """
    Encapsulate a shared secret using ML-KEM-768
    
    Args:
        public_key: Base64 encoded ML-KEM-768 public key
    
    Returns:
        Tuple of (ciphertext, shared_secret) as base64 strings
    """
    return PQCKeyManager.encapsulate(public_key)


def kyber_decapsulate(ciphertext: str, private_key: str) -> str:
    """
    Decapsulate shared secret using ML-KEM-768
    
    Args:
        ciphertext: Base64 encoded ciphertext
        private_key: Base64 encoded ML-KEM-768 private key
    
    Returns:
        Base64 encoded shared secret
    """
    return PQCKeyManager.decapsulate(ciphertext, private_key)


def dilithium_sign(message: str, private_key: str, public_key: str) -> str:
    """
    Sign a message using ML-DSA-65
    
    Args:
        message: Message to sign
        private_key: Base64 encoded ML-DSA-65 private key
        public_key: Base64 encoded ML-DSA-65 public key
    
    Returns:
        Base64 encoded signature
    """
    return PQCKeyManager.sign(message, private_key, public_key)


def dilithium_verify(message: str, signature: str, public_key: str) -> bool:
    """
    Verify ML-DSA-65 digital signature
    
    Args:
        message: Original message
        signature: Base64 encoded signature
        public_key: Base64 encoded ML-DSA-65 public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    return PQCKeyManager.verify(message, signature, public_key)


def is_pqc_available() -> bool:
    """
    Check if PQC (liboqs) is available
    
    Returns:
        True if liboqs is installed and functional
    """
    return PQCKeyManager.is_available()


def get_pqc_info() -> dict:
    """
    Get information about PQC algorithms
    
    Returns:
        Dictionary with algorithm information
    """
    return PQCKeyManager.get_algorithm_info()

