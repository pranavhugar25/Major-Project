"""
Cryptographic utilities for the backend
Handles hashing, PQC key generation, and verification
"""
import hashlib
import secrets
import base64
from typing import Tuple, Optional
import os


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


class PQCKeyManager:
    """
    Manager for Post-Quantum Cryptography keys
    Handles ML-KEM (Kyber) and ML-DSA (Dilithium) key generation
    
    Note: This is a simplified implementation for demonstration.
    In production, use actual PQC libraries like liboqs or pqcrypto
    """
    
    @staticmethod
    def generate_kyber_keypair() -> Tuple[str, str]:
        """
        Generate ML-KEM (Kyber) key pair for key encapsulation
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
            
        Note: This is a placeholder. In production, use actual Kyber implementation
        """
        # Simulated Kyber-1024 keys (actual implementation would use kyber-py or liboqs)
        # Public key: ~1568 bytes, Private key: ~3168 bytes
        public_key = secrets.token_bytes(1568)
        private_key = secrets.token_bytes(3168)
        
        return (
            base64.b64encode(public_key).decode('utf-8'),
            base64.b64encode(private_key).decode('utf-8')
        )
    
    @staticmethod
    def generate_dilithium_keypair() -> Tuple[str, str]:
        """
        Generate ML-DSA (Dilithium) key pair for digital signatures
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
            
        Note: This is a placeholder. In production, use actual Dilithium implementation
        """
        # Simulated Dilithium5 keys (actual implementation would use dilithium-py or liboqs)
        # Public key: ~2592 bytes, Private key: ~4864 bytes
        public_key = secrets.token_bytes(2592)
        private_key = secrets.token_bytes(4864)
        
        return (
            base64.b64encode(public_key).decode('utf-8'),
            base64.b64encode(private_key).decode('utf-8')
        )
    
    @staticmethod
    def kyber_encapsulate(public_key: str) -> Tuple[str, str]:
        """
        Encapsulate a shared secret using Kyber public key
        
        Args:
            public_key: Base64 encoded Kyber public key
        
        Returns:
            Tuple of (ciphertext, shared_secret) as base64 strings
        """
        # Simulated encapsulation (actual implementation would use kyber-py)
        ciphertext = secrets.token_bytes(1568)
        shared_secret = secrets.token_bytes(32)
        
        return (
            base64.b64encode(ciphertext).decode('utf-8'),
            base64.b64encode(shared_secret).decode('utf-8')
        )
    
    @staticmethod
    def kyber_decapsulate(private_key: str, ciphertext: str) -> str:
        """
        Decapsulate shared secret using Kyber private key
        
        Args:
            private_key: Base64 encoded Kyber private key
            ciphertext: Base64 encoded ciphertext
        
        Returns:
            Base64 encoded shared secret
        """
        # Simulated decapsulation (actual implementation would use kyber-py)
        shared_secret = secrets.token_bytes(32)
        return base64.b64encode(shared_secret).decode('utf-8')
    
    @staticmethod
    def dilithium_sign(private_key: str, message: str) -> str:
        """
        Sign a message using Dilithium private key
        
        Args:
            private_key: Base64 encoded Dilithium private key
            message: Message to sign
        
        Returns:
            Base64 encoded signature
        """
        # Simulated signing (actual implementation would use dilithium-py)
        signature = secrets.token_bytes(4595)
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def dilithium_verify(public_key: str, message: str, signature: str) -> bool:
        """
        Verify a Dilithium signature
        
        Args:
            public_key: Base64 encoded Dilithium public key
            message: Original message
            signature: Base64 encoded signature
        
        Returns:
            True if signature is valid, False otherwise
        """
        # Simulated verification (actual implementation would use dilithium-py)
        # In a real implementation, this would cryptographically verify
        return True


def derive_vault_key_server_side(master_password: str, salt: str) -> str:
    """
    Derive vault key on server side (for comparison/verification only)
    
    NOTE: In a true zero-knowledge system, this should NEVER be called.
    The vault key should only be derived client-side.
    This function exists only for demonstration and testing purposes.
    
    Args:
        master_password: Master password
        salt: Base64 encoded salt
    
    Returns:
        Base64 encoded vault key
    """
    salt_bytes = base64.b64decode(salt)
    
    # Derive 256-bit key using PBKDF2
    vault_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        salt_bytes,
        iterations=600000,
        dklen=32
    )
    
    return base64.b64encode(vault_key).decode('utf-8')
