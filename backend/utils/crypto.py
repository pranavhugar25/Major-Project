"""
Cryptographic utilities for the backend
Handles hashing, PQC key generation, OPRF, and verification
"""
import base64
import hashlib
import os
import secrets
from typing import Optional, Tuple

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Import real PQC from liboqs
from utils.pqc import PQCKeyManager

# Import SPAKE2 functions for PAKE authentication
from utils.spake2_pake import (
    generate_password_verifier,
    compute_verifier,
    create_server,
    create_client
)

def is_spake2_available() -> bool:
    """
    Check if SPAKE2 is available
    
    Returns:
        True if spake2 is installed and functional
    """
    return True


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


ARGON2ID_LENGTH = 32
ARGON2ID_ITERATIONS = 3
ARGON2ID_MEMORY_COST = 64 * 1024
ARGON2ID_LANES = 4
PBKDF2_ITERATIONS = 600000
PBKDF2_LENGTH = 32


def _derive_argon2id_key(password: str, salt_bytes: bytes) -> bytes:
    """Derive a master-password hash using Argon2id."""
    kdf = Argon2id(
        salt=salt_bytes,
        length=ARGON2ID_LENGTH,
        iterations=ARGON2ID_ITERATIONS,
        lanes=ARGON2ID_LANES,
        memory_cost=ARGON2ID_MEMORY_COST,
    )
    return kdf.derive(password.encode('utf-8'))


def _derive_pbkdf2_key(password: str, salt_bytes: bytes) -> bytes:
    """Derive the legacy master-password hash using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        iterations=PBKDF2_ITERATIONS,
        dklen=PBKDF2_LENGTH,
    )


def hash_password(password: str, salt: str) -> str:
    """
    Hash password using Argon2id.

    This is the primary master-password hashing algorithm used for new
    registrations and password upgrades.
    
    Args:
        password: Plain text password
        salt: Base64 encoded salt
    
    Returns:
        Base64 encoded password hash
    """
    salt_bytes = base64.b64decode(salt)

    password_hash = _derive_argon2id_key(password, salt_bytes)

    return base64.b64encode(password_hash).decode('utf-8')


def verify_password_with_algorithm(password: str, salt: str, stored_hash: str) -> Tuple[bool, Optional[str]]:
    """
    Verify password against the stored hash.

    Returns:
        A tuple of (is_valid, algorithm_name). The algorithm name is
        'argon2id' or 'pbkdf2' when verification succeeds.
    """
    salt_bytes = base64.b64decode(salt)

    try:
        stored_hash_bytes = base64.b64decode(stored_hash)
    except Exception:
        return False, None

    try:
        argon2id_hash = _derive_argon2id_key(password, salt_bytes)
        if secrets.compare_digest(argon2id_hash, stored_hash_bytes):
            return True, 'argon2id'
    except Exception:
        pass

    try:
        pbkdf2_hash = _derive_pbkdf2_key(password, salt_bytes)
        if secrets.compare_digest(pbkdf2_hash, stored_hash_bytes):
            return True, 'pbkdf2'
    except Exception:
        pass

    return False, None


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
    is_valid, _ = verify_password_with_algorithm(password, salt, stored_hash)
    return is_valid


# ============================================================================
# Post-Quantum Cryptography - Real Implementation using liboqs
# ============================================================================
# These functions provide the real PQC operations using ML-KEM-1024 and
# ML-DSA-87 from the liboqs library (NIST-standardized).
# 
# See utils/pqc.py for the full implementation.
# ============================================================================

def generate_kyber_keypair() -> Tuple[str, str]:
    """
    Generate ML-KEM-1024 key pair for key encapsulation
    
    Returns:
        Tuple of (public_key, private_key) as base64 strings
        
    Note:
        Uses liboqs-python for NIST-standard ML-KEM-1024 implementation.
        This provides quantum-resistant key encapsulation.
    """
    return PQCKeyManager.generate_kyber_keypair()


def generate_dilithium_keypair() -> Tuple[str, str]:
    """
    Generate ML-DSA-87 key pair for digital signatures
    
    Returns:
        Tuple of (public_key, private_key) as base64 strings
        
    Note:
        Uses liboqs-python for NIST-standard ML-DSA-87 implementation.
        This provides quantum-resistant digital signatures.
    """
    return PQCKeyManager.generate_dilithium_keypair()


def kyber_encapsulate(public_key: str) -> Tuple[str, str]:
    """
    Encapsulate a shared secret using ML-KEM-1024
    
    Args:
        public_key: Base64 encoded ML-KEM-1024 public key
    
    Returns:
        Tuple of (ciphertext, shared_secret) as base64 strings
    """
    return PQCKeyManager.encapsulate(public_key)


def kyber_decapsulate(ciphertext: str, private_key: str) -> str:
    """
    Decapsulate shared secret using ML-KEM-1024
    
    Args:
        ciphertext: Base64 encoded ciphertext
        private_key: Base64 encoded ML-KEM-1024 private key
    
    Returns:
        Base64 encoded shared secret
    """
    return PQCKeyManager.decapsulate(ciphertext, private_key)


def dilithium_sign(message: str, private_key: str, public_key: str) -> str:
    """
    Sign a message using ML-DSA-87
    
    Args:
        message: Message to sign
        private_key: Base64 encoded ML-DSA-87 private key
        public_key: Base64 encoded ML-DSA-87 public key
    
    Returns:
        Base64 encoded signature
    """
    return PQCKeyManager.sign(message, private_key, public_key)


def dilithium_verify(message: str, signature: str, public_key: str) -> bool:
    """
    Verify ML-DSA-87 digital signature
    
    Args:
        message: Original message
        signature: Base64 encoded signature
        public_key: Base64 encoded ML-DSA-87 public key
    
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

