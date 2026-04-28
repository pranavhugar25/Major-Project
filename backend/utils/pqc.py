"""
Real Post-Quantum Cryptography using liboqs
ML-KEM-1024 for key encapsulation
ML-DSA-87 for digital signatures

This module implements NIST-standardized post-quantum cryptographic
algorithms for quantum-resistant security.

Reference: https://github.com/open-quantum-safe/liboqs
NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
"""
import base64
import logging
import os
from typing import Tuple, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Try to import oqs (liboqs-python), provide helpful error if not available
LIBOQS_AVAILABLE = False
logger.info("[PQC] Attempting to import liboqs Python bindings...")

try:
    import oqs
    logger.info(f"[PQC] Imported 'oqs' module from: {oqs.__file__}")
    from oqs import KeyEncapsulation, Signature
    LIBOQS_AVAILABLE = True
    logger.info("[PQC] ✓ liboqs Python bindings loaded successfully")
    
    # Query enabled mechanisms
    try:
        enabled_kems = oqs.get_enabled_kem_mechanisms()
        enabled_sigs = oqs.get_enabled_sig_mechanisms()
        logger.info(f"[PQC] Enabled KEMs: {enabled_kems}")
        logger.info(f"[PQC] Enabled Signatures: {enabled_sigs}")
        if 'ML-KEM-1024' in enabled_kems:
            logger.info("[PQC] ✓ ML-KEM-1024 is ENABLED")
        else:
            logger.warning("[PQC] ✗ ML-KEM-1024 is NOT enabled in liboqs build")
        if 'ML-DSA-87' in enabled_sigs:
            logger.info("[PQC] ✓ ML-DSA-87 is ENABLED")
        else:
            logger.warning("[PQC] ✗ ML-DSA-87 is NOT enabled in liboqs build")
    except AttributeError as e:
        logger.warning(f"[PQC] Could not query mechanisms via module API: {e}")
    
    # Note: Operational self-test is performed at module load time via _run_self_test()
    
except ImportError as e:
    LIBOQS_AVAILABLE = False
    logger.error(
        f"[PQC] ✗ Failed to import liboqs Python bindings: {e}. "
        "PQC features will be DISABLED."
    )
    logger.error(f"[PQC] LD_LIBRARY_PATH: {os.environ.get('LD_LIBRARY_PATH', 'NOT SET')}")
    import traceback
    logger.error(f"[PQC] Import traceback: {traceback.format_exc()}")
    logger.error(f"[PQC] Current LD_LIBRARY_PATH: {os.environ.get('LD_LIBRARY_PATH', 'NOT SET')}")
    import traceback
    logger.error(f"[PQC] Import traceback: {traceback.format_exc()}")


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


# In-memory server signing keypair (generated at startup)
_server_mldsa_public_key: str = None
_server_mldsa_private_key: str = None

def init_server_signing_keypair():
    """Generate server's ML-DSA-87 keypair for signing session data"""
    global _server_mldsa_public_key, _server_mldsa_private_key
    if not LIBOQS_AVAILABLE:
        logger.warning("[PQC] Cannot generate signing keypair - liboqs not available")
        return
    
    try:
        keypair = MLDSA87.generate_keypair()
        _server_mldsa_public_key = keypair.public_key
        _server_mldsa_private_key = keypair.private_key
        logger.info(f"[PQC] ✓ Server ML-DSA-87 signing keypair generated")
        logger.info(f"[PQC]   Public key length: {len(_server_mldsa_public_key)} chars")
    except Exception as e:
        logger.error(f"[PQC] Failed to generate server signing keypair: {e}")

def get_server_mldsa_public_key() -> str:
    """Get server's ML-DSA public key for signature verification"""
    return _server_mldsa_public_key

def sign_session_data(data: str) -> str:
    """Sign data using server's ML-DSA-87 private key"""
    if not _server_mldsa_private_key:
        raise PQCError("Server signing key not initialized")
    
    try:
        # Sign the session_id string
        message_bytes = data.encode('utf-8')
        logger.info(f"[PQC] Signing message: len={len(message_bytes)} bytes")
        
        signature = MLDSA87.sign(data, _server_mldsa_private_key, _server_mldsa_public_key)
        
        logger.info(f"[PQC] Signature generated: len={len(signature)} chars (base64)")
        logger.info(f"[PQC] Signature (first 50 chars): {signature[:50]}")
        
        return signature
    except Exception as e:
        logger.error(f"[PQC] Signing failed: {e}")
        raise PQCError(f"Signing failed: {e}")

def verify_session_signature(data: str, signature: str, public_key: str) -> bool:
    """Verify ML-DSA-87 signature"""
    return MLDSA87.verify(data, signature, public_key)


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


class MLKEM1024:
    """
    ML-KEM-1024 (formerly Kyber) Key Encapsulation Mechanism
    
    NIST Level 5 security (approximately AES-256 equivalent)
    Key sizes:
    - Public key: 1568 bytes
    - Secret key: 3168 bytes
    - Ciphertext: 1568 bytes
    - Shared secret: 32 bytes
    """
    
    ALGORITHM = "ML-KEM-1024"
    
    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        """
        Generate ML-KEM-1024 key pair

        Returns:
            PQCKeyPair with base64-encoded public and private keys

        Raises:
            PQCUnavailableError: If liboqs is not installed
        """
        _check_liboqs()

        try:
            with KeyEncapsulation(MLKEM1024.ALGORITHM) as kem:
                public_key = kem.generate_keypair()  # Returns bytes (public key)
                secret_key = kem.export_secret_key()  # Export private key

                return PQCKeyPair(
                    public_key=base64.b64encode(public_key).decode('utf-8'),
                    private_key=base64.b64encode(secret_key).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-KEM-1024 key generation failed: {e}")
            raise PQCError(f"Key generation failed: {e}")

    @staticmethod
    def encapsulate(public_key_b64: str) -> KEMResult:
        """
        Encapsulate a shared secret using ML-KEM-1024

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

            with KeyEncapsulation(MLKEM1024.ALGORITHM) as kem:
                ciphertext, shared_secret = kem.encap_secret(public_key)

                return KEMResult(
                    ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
                    shared_secret=base64.b64encode(shared_secret).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-KEM-1024 encapsulation failed: {e}")
            raise PQCError(f"Encapsulation failed: {e}")

    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        """
        Decapsulate shared secret using ML-KEM-1024

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

            # liboqs: Create KEM instance with private key for decapsulation
            with KeyEncapsulation(MLKEM1024.ALGORITHM, private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
                return base64.b64encode(shared_secret).decode('utf-8')
        except Exception as e:
            logger.error(f"ML-KEM-1024 decapsulation failed: {e}")
            raise PQCError(f"Decapsulation failed: {e}")


class MLDSA87:
    """
    ML-DSA-87 (formerly Dilithium) Digital Signature Algorithm
    
    NIST Level 5 security (approximately AES-256 equivalent)
    Key sizes:
    - Public key: 2592 bytes
    - Secret key: 4896 bytes
    - Signature: ~4627 bytes (variable)
    """
    
    ALGORITHM = "ML-DSA-87"
    
    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        """
        Generate ML-DSA-87 key pair
        
        Returns:
            PQCKeyPair with base64-encoded public and private keys
            
        Raises:
            PQCUnavailableError: If liboqs is not installed
            PQCError: If key generation fails
        """
        _check_liboqs()
        
        try:
            with Signature(MLDSA87.ALGORITHM) as sig:
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()
                
                return PQCKeyPair(
                    public_key=base64.b64encode(public_key).decode('utf-8'),
                    private_key=base64.b64encode(secret_key).decode('utf-8')
                )
        except Exception as e:
            logger.error(f"ML-DSA-87 key generation failed: {e}")
            raise PQCError(f"Key generation failed: {e}")
    
    @staticmethod
    def sign(message: str, private_key_b64: str, public_key_b64: str) -> str:
        """
        Create ML-DSA-87 digital signature
        
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
            
            with Signature(MLDSA87.ALGORITHM, private_key) as sig:
                signature = sig.sign(message_bytes)
                return base64.b64encode(signature).decode('utf-8')
        except Exception as e:
            logger.error(f"ML-DSA-87 signing failed: {e}")
            raise PQCError(f"Signing failed: {e}")
    
    @staticmethod
    def verify(message: str, signature_b64: str, public_key_b64: str) -> bool:
        """
        Verify ML-DSA-87 digital signature
        
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
            
            logger.info(f"[PQC] Verify: msg_len={len(message_bytes)}, sig_len={len(signature)}, pub_len={len(public_key)}")
            
            with Signature(MLDSA87.ALGORITHM) as sig:
                result = sig.verify(message_bytes, signature, public_key)
                logger.info(f"[PQC] Verify result: {result}")
                return result
        except Exception as e:
            logger.warning(f"ML-DSA-87 verification failed: {e}")
            import traceback
            logger.warning(f"Traceback: {traceback.format_exc()}")
            return False


class PQCKeyManager:
    """
    Unified manager for Post-Quantum Cryptography operations
    
    Provides simplified interface for:
    - ML-KEM-1024 key encapsulation (for session key exchange)
    - ML-DSA-87 digital signatures (for authentication)
    """
    
    # Algorithm constants
    KEM_ALGORITHM = "ML-KEM-1024"
    SIG_ALGORITHM = "ML-DSA-87"
    
    @staticmethod
    def generate_kyber_keypair() -> Tuple[str, str]:
        """
        Generate ML-KEM-1024 key pair for key encapsulation
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
        """
        keypair = MLKEM1024.generate_keypair()
        return (keypair.public_key, keypair.private_key)
    
    @staticmethod
    def generate_dilithium_keypair() -> Tuple[str, str]:
        """
        Generate ML-DSA-87 key pair for digital signatures
        
        Returns:
            Tuple of (public_key, private_key) as base64 strings
        """
        keypair = MLDSA87.generate_keypair()
        return (keypair.public_key, keypair.private_key)
    
    @staticmethod
    def encapsulate(public_key_b64: str) -> KEMResult:
        """
        Encapsulate shared secret using ML-KEM-1024

        Args:
            public_key_b64: Base64-encoded Kyber public key

        Returns:
            KEMResult with ciphertext and shared_secret (both base64-encoded)
        """
        result = MLKEM1024.encapsulate(public_key_b64)
        return result

    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        """
        Decapsulate shared secret using ML-KEM-1024

        Args:
            ciphertext_b64: Base64-encoded ciphertext
            private_key_b64: Base64-encoded private key

        Returns:
            Base64-encoded shared secret
        """
        return MLKEM1024.decapsulate(ciphertext_b64, private_key_b64)
    
    @staticmethod
    def sign(message: str, private_key_b64: str, public_key_b64: str) -> str:
        """
        Sign message using ML-DSA-87
        
        Args:
            message: Message to sign
            private_key_b64: Base64-encoded private key
            public_key_b64: Base64-encoded public key
            
        Returns:
            Base64-encoded signature
        """
        return MLDSA87.sign(message, private_key_b64, public_key_b64)
    
    @staticmethod
    def verify(message: str, signature_b64: str, public_key_b64: str) -> bool:
        """
        Verify ML-DSA-87 signature
        
        Args:
            message: Original message
            signature_b64: Base64-encoded signature
            public_key_b64: Base64-encoded public key
            
        Returns:
            True if signature is valid, False otherwise
        """
        return MLDSA87.verify(message, signature_b64, public_key_b64)
    
    @staticmethod
    def is_available() -> bool:
        """
        Check if liboqs is available and functional
        
        Returns:
            True if liboqs is installed and working
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
            "kem_algorithm": MLKEM1024.ALGORITHM if LIBOQS_AVAILABLE else None,
            "sig_algorithm": MLDSA87.ALGORITHM if LIBOQS_AVAILABLE else None,
            "available": LIBOQS_AVAILABLE,
            "nist_level": 5,
            "description": "NIST Level 5 post-quantum cryptography"
        }


# ============================================================================
# Runtime self-test (runs on module import)
# ============================================================================

def _run_self_test():
    """Run a quick self-test to verify PQC operations work"""
    if not LIBOQS_AVAILABLE:
        logger.warning("[PQC] Self-test SKIPPED: liboqs not available")
        return False

    logger.info("[PQC] Running self-test to verify operations...")
    try:
        # Test 1: Key generation via our wrapper
        keypair = MLKEM1024.generate_keypair()
        logger.info(f"[PQC] ✓ Key generation: pub={len(keypair.public_key)} chars, priv={len(keypair.private_key)} chars")

        # Test 2: Encapsulation
        result = MLKEM1024.encapsulate(keypair.public_key)
        logger.info(f"[PQC] ✓ Encapsulation: ct={len(result.ciphertext)} chars, ss={len(result.shared_secret)} chars")

        # Test 3: Decapsulation
        recovered_ss_b64 = MLKEM1024.decapsulate(result.ciphertext, keypair.private_key)
        logger.info(f"[PQC] ✓ Decapsulation: recovered secret length={len(recovered_ss_b64)}")

        # Test 4: Verify shared secrets match
        if result.shared_secret == recovered_ss_b64:
            logger.info("[PQC] ✓✓✓ Self-test PASSED: Shared secrets match")
            return True
        else:
            logger.error("[PQC] ✗ Self-test FAILED: Shared secrets do NOT match")
            logger.error(f"[PQC] Expected: {result.shared_secret[:50]}...")
            logger.error(f"[PQC] Got: {recovered_ss_b64[:50]}...")
            return False

    except Exception as e:
        logger.error(f"[PQC] ✗ Self-test FAILED with exception: {e}")
        import traceback
        logger.error(f"[PQC] Traceback: {traceback.format_exc()}")
        return False


# Run self-test at module load time (only if LIBOQS_AVAILABLE)
_SELF_TEST_RESULT = _run_self_test() if LIBOQS_AVAILABLE else False
