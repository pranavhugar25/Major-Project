"""
Real Post-Quantum Cryptography using liboqs
ML-KEM-768 for key encapsulation
ML-DSA-65 for digital signatures

This module implements NIST-standardized post-quantum cryptographic
algorithms for quantum-resistant security.

Reference: https://github.com/open-quantum-safe/liboqs
NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
"""
import base64
import logging
from typing import Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import liboqs, provide helpful error if not available
try:
    import liboqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False
    logger.warning(
        "liboqs not installed. PQC features will be disabled. "
        "Install with: pip install liboqs-python"
    )


@dataclass
class PQCKeyPair:
    """Container for PQC key pair"""
    public_key: str
    private_key: str


@dataclass
class KEMResult:
    """Result of key encapsulation"""
    ciphertext: str
    shared_secret: str


@dataclass
class SignatureResult:
    """Result of digital signature"""
    signature: str


class PQCError(Exception):
    """Base exception for PQC operations"""
    pass


class PQCUnavailableError(PQCError):
    """Raised when liboqs is not available"""
    pass


class PQCVerificationError(PQCError):
    """Raised when signature verification fails"""
    pass


def _check_liboqs() -> None:
    """Verify liboqs is available"""
    if not LIBOQS_AVAILABLE:
        raise PQCUnavailableError(
            "liboqs is required for PQC operations. "
            "Install with: pip install liboqs-python"
        )


class MLKEM768:
    """
    ML-KEM-768 (formerly Kyber) Key Encapsulation Mechanism
    
    NIST Level 3 security (approximately AES-128 equivalent)
    Key sizes:
    - Public key: 1184 bytes
    - Secret key: 2400 bytes
    - Ciphertext: 1088 bytes
    - Shared secret: 32 bytes
    """
    
    ALGORITHM = "ML-KEM-768"
    
    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        """
        Generate ML-KEM-768 key pair
        
        Returns:
            PQCKeyPair with base64-encoded public and private keys
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
        """
        _check_liboqs()
        
        try:
            with liboqs.KeyEncapsulation(MLKEM768.ALGORITHM) as kem:
                public_key = kem.generate_public_key()
                secret_key = kem.generate_secret_key()
                
                return PQCKeyPair(
                    public_key=base64.b64encode(public_key).decode('utf-8'),
                    private_key=base64.b64encode(secret_key).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-KEM-768 key generation failed: {e}")
            raise PQCError(f"Key generation failed: {e}")
    
    @staticmethod
    def encapsulate(public_key_b64: str) -> KEMResult:
        """
        Encapsulate a shared secret using ML-KEM-768
        
        Args:
            public_key_b64: Base64-encoded public key
            
        Returns:
            KEMResult with ciphertext and shared_secret (both base64-encoded)
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If encapsulation fails
        """
        _check_liboqs()
        
        try:
            public_key = base64.b64decode(public_key_b64)
            
            with liboqs.KeyEncapsulation(MLKEM768.ALGORITHM) as kem:
                ciphertext = kem.encap_secret(public_key)
                shared_secret = kem.export_shared_secret()
                
                return KEMResult(
                    ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
                    shared_secret=base64.b64encode(shared_secret).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-KEM-768 encapsulation failed: {e}")
            raise PQCError(f"Encapsulation failed: {e}")
    
    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        """
        Decapsulate shared secret using ML-KEM-768
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            private_key_b64: Base64-encoded private key
            
        Returns:
            Base64-encoded shared secret
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If decapsulation fails
        """
        _check_liboqs()
        
        try:
            ciphertext = base64.b64decode(ciphertext_b64)
            private_key = base64.b64decode(private_key_b64)
            
            with liboqs.KeyEncapsulation(MLKEM768.ALGORITHM, private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                return base64.b64encode(shared_secret).decode('utf-8')
        except Exception as e:
            logger.error(f"ML-KEM-768 decapsulation failed: {e}")
            raise PQCError(f"Decapsulation failed: {e}")


class MLDSA65:
    """
    ML-DSA-65 (formerly Dilithium) Digital Signature Algorithm
    
    NIST Level 3 security (approximately AES-192 equivalent)
    Key sizes:
    - Public key: 2592 bytes
    - Secret key: 4000 bytes
    - Signature: ~3295 bytes (variable)
    """
    
    ALGORITHM = "ML-DSA-65"
    
    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        """
        Generate ML-DSA-65 key pair
        
        Returns:
            PQCKeyPair with base64-encoded public and private keys
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If key generation fails
        """
        _check_liboqs()
        
        try:
            with liboqs.Signature(MLDSA65.ALGORITHM) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key(public_key)
                
                return PQCKeyPair(
                    public_key=base64.b64encode(public_key).decode('utf-8'),
                    private_key=base64.b64encode(secret_key).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-DSA-65 key generation failed: {e}")
            raise PQCError(f"Key generation failed: {e}")
    
    @staticmethod
    def sign(message: str, private_key_b64: str, public_key_b64: str) -> str:
        """
        Create ML-DSA-65 digital signature
        
        Args:
            message: Message to sign (utf-8 string)
            private_key_b64: Base64-encoded private key
            public_key_b64: Base64-encoded public key
            
        Returns:
            Base64-encoded signature
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If signing fails
        """
        _check_liboqs()
        
        try:
            message_bytes = message.encode('utf-8')
            private_key = base64.b64decode(private_key_b64)
            public_key = base64.b64decode(public_key_b64)
            
            with liboqs.Signature(MLDSA65.ALGORITHM, public_key) as sig:
                signature = sig.sign(message_bytes, private_key)
                return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"ML-DSA-65 signing failed: {e}")
            raise PQCError(f"Signing failed: {e}")
    
    @staticmethod
    def verify(message: str, signature_b64: str, public_key_b64: str) -> bool:
        """
        Verify ML-DSA-65 digital signature
        
        Args:
            message: Original message (utf-8 string)
            signature_b64: Base64-encoded signature
            public_key_b64: Base64-encoded public key
            
        Returns:
            True if signature is valid, False if invalid
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If verification fails (likely due to corrupted data)
        """
        _check_liboqs()
        
        try:
            message_bytes = message.encode('utf-8')
            signature = base64.b64decode(signature_b64)
            public_key = base64.b64decode(public_key_b64)
            
            with liboqs.Signature(MLDSA65.ALGORITHM) as sig:
                return sig.verify(message_bytes, signature, public_key)
        except Exception as e:
            logger.warning(f"ML-DSA-65 verification failed: {e}")
            return False


class PQCKeyManager:
    """
    Unified manager for Post-Quantum Cryptography operations
    
    Provides simplified interface for:
    - ML-KEM-768 key encapsulation (for session key exchange)
    - ML-DSA-65 digital signatures (for authentication)
    """
    
    # Algorithm constants
    KEM_ALGORITHM = "ML-KEM-768"
    SIG_ALGORITHM = "ML-DSA-65"
    
    @staticmethod
    def generate_kyber_keypair() -> Tuple[str, str]:
        """
        Generate ML-KEM-768 key pair for key encapsulation
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
            
        Note:
            This is the primary method for establishing quantum-resistant
            session keys between client and server.
        """
        keypair = MLKEM768.generate_keypair()
        return (keypair.public_key, keypair.private_key)
    
    @staticmethod
    def generate_dilithium_keypair() -> Tuple[str, str]:
        """
        Generate ML-DSA-65 key pair for digital signatures
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
            
        Note:
            This is used for server authentication and message signing.
        """
        keypair = MLDSA65.generate_keypair()
        return (keypair.public_key, keypair.private_key)
    
    @staticmethod
    def encapsulate(public_key_b64: str) -> Tuple[str, str]:
        """
        Encapsulate shared secret using ML-KEM-768
        
        Args:
            public_key_b64: Base64-encoded Kyber public key
            
        Returns:
            Tuple of (ciphertext, shared_secret) as base64 strings
            
        Note:
            The shared secret can be used for symmetric encryption.
        """
        result = MLKEM768.encapsulate(public_key_b64)
        return (result.ciphertext, result.shared_secret)
    
    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        """
        Decapsulate shared secret using ML-KEM-768
        
        Args:
            ciphertext_b64: Base64-encoded ciphertext
            private_key_b64: Base64-encoded private key
            
        Returns:
            Base64-encoded shared secret
        """
        return MLKEM768.decapsulate(ciphertext_b64, private_key_b64)
    
    @staticmethod
    def sign(message: str, private_key_b64: str, public_key_b64: str) -> str:
        """
        Sign message using ML-DSA-65
        
        Args:
            message: Message to sign
            private_key_b64: Base64-encoded private key
            public_key_b64: Base64-encoded public key
            
        Returns:
            Base64-encoded signature
        """
        return MLDSA65.sign(message, private_key_b64, public_key_b64)
    
    @staticmethod
    def verify(message: str, signature_b64: str, public_key_b64: str) -> bool:
        """
        Verify ML-DSA-65 signature
        
        Args:
            message: Original message
            signature_b64: Base64-encoded signature
            public_key_b64: Base64-encoded public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        return MLDSA65.verify(message, signature_b64, public_key_b64)
    
    @staticmethod
    def is_available() -> bool:
        """
        Check if liboqs is available
        
        Returns:
            True if liboqs is installed and functional
        """
        return LIBOQS_AVAILABLE
    
    @staticmethod
    def get_algorithm_info() -> dict:
        """
        Get information about enabled PQC algorithms
        
        Returns:
            Dictionary with algorithm information
        """
        return {
            "kem_algorithm": MLKEM768.ALGORITHM if LIBOQS_AVAILABLE else None,
            "sig_algorithm": MLDSA65.ALGORITHM if LIBOQS_AVAILABLE else None,
            "available": LIBOQS_AVAILABLE,
            "nist_level": 3,
            "description": "NIST Level 3 post-quantum cryptography"
        }
