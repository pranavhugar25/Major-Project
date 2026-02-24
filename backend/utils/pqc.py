"""
Post-Quantum Cryptography helpers backed by liboqs-python.

Algorithms:
- ML-KEM-1024 (KEM, NIST Level 5)
- ML-DSA-87 (signature, NIST Level 5)
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Dict, Tuple

logger = logging.getLogger(__name__)

try:
    from oqs import KeyEncapsulation, Signature, oqs_python_version, oqs_version

    LIBOQS_AVAILABLE = True
    LIBOQS_ERROR = None
except ImportError as exc:  # pragma: no cover - exercised in environments without liboqs
    LIBOQS_AVAILABLE = False
    LIBOQS_ERROR = str(exc)
    KeyEncapsulation = None  # type: ignore[assignment]
    Signature = None  # type: ignore[assignment]


@dataclass
class PQCKeyPair:
    """Container for base64-encoded public/private key pair."""

    public_key: str
    private_key: str


@dataclass
class KEMResult:
    """Container for base64-encoded KEM output."""

    ciphertext: str
    shared_secret: str


class PQCError(Exception):
    """Raised when a PQC primitive fails."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


class MLKEM1024:
    """ML-KEM-1024 wrapper."""

    ALGORITHM = "ML-KEM-1024"

    @staticmethod
    def is_available() -> bool:
        if not LIBOQS_AVAILABLE:
            return False
        try:
            with KeyEncapsulation(MLKEM1024.ALGORITHM):
                return True
        except Exception:
            return False

    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        try:
            with KeyEncapsulation(MLKEM1024.ALGORITHM) as kem:
                public_key = kem.generate_keypair()
                private_key = kem.export_secret_key()
            return PQCKeyPair(public_key=_b64e(public_key), private_key=_b64e(private_key))
        except Exception as exc:
            logger.error("ML-KEM key generation failed: %s", exc)
            raise PQCError(f"ML-KEM key generation failed: {exc}") from exc

    @staticmethod
    def encapsulate(public_key_b64: str) -> KEMResult:
        try:
            public_key = _b64d(public_key_b64)
            with KeyEncapsulation(MLKEM1024.ALGORITHM) as kem:
                # liboqs-python versions differ: some return tuple, some return ciphertext only.
                encap_result = kem.encap_secret(public_key)
                if isinstance(encap_result, tuple):
                    ciphertext, shared_secret = encap_result
                else:
                    ciphertext = encap_result
                    shared_secret = kem.decap_secret(ciphertext)
            return KEMResult(ciphertext=_b64e(ciphertext), shared_secret=_b64e(shared_secret))
        except Exception as exc:
            logger.error("ML-KEM encapsulation failed: %s", exc)
            raise PQCError(f"ML-KEM encapsulation failed: {exc}") from exc

    @staticmethod
    def decapsulate(ciphertext_b64: str, private_key_b64: str) -> str:
        try:
            ciphertext = _b64d(ciphertext_b64)
            private_key = _b64d(private_key_b64)
            with KeyEncapsulation(MLKEM1024.ALGORITHM, secret_key=private_key) as kem:
                shared_secret = kem.decap_secret(ciphertext)
            return _b64e(shared_secret)
        except Exception as exc:
            logger.error("ML-KEM decapsulation failed: %s", exc)
            raise PQCError(f"ML-KEM decapsulation failed: {exc}") from exc


class MLDSA87:
    """ML-DSA-87 wrapper."""

    ALGORITHM = "ML-DSA-87"

    @staticmethod
    def is_available() -> bool:
        if not LIBOQS_AVAILABLE:
            return False
        try:
            with Signature(MLDSA87.ALGORITHM):
                return True
        except Exception:
            return False

    @staticmethod
    def generate_keypair() -> PQCKeyPair:
        try:
            with Signature(MLDSA87.ALGORITHM) as sig:
                generated = sig.generate_keypair()
                if isinstance(generated, tuple):
                    public_key, private_key = generated
                else:
                    public_key = generated
                    private_key = sig.export_secret_key()
            return PQCKeyPair(public_key=_b64e(public_key), private_key=_b64e(private_key))
        except Exception as exc:
            logger.error("ML-DSA key generation failed: %s", exc)
            raise PQCError(f"ML-DSA key generation failed: {exc}") from exc

    @staticmethod
    def sign(message: bytes, private_key_b64: str) -> str:
        try:
            private_key = _b64d(private_key_b64)
            with Signature(MLDSA87.ALGORITHM, secret_key=private_key) as sig:
                signature = sig.sign(message)
            return _b64e(signature)
        except Exception as exc:
            logger.error("ML-DSA signing failed: %s", exc)
            raise PQCError(f"ML-DSA signing failed: {exc}") from exc

    @staticmethod
    def verify(message: bytes, signature_b64: str, public_key_b64: str) -> bool:
        try:
            signature = _b64d(signature_b64)
            public_key = _b64d(public_key_b64)
            with Signature(MLDSA87.ALGORITHM) as sig:
                return bool(sig.verify(message, signature, public_key))
        except Exception as exc:
            logger.warning("ML-DSA verification failed: %s", exc)
            return False


class PQCKeyManager:
    """Facade used by the rest of the backend."""

    @staticmethod
    def is_available() -> bool:
        return LIBOQS_AVAILABLE and MLKEM1024.is_available() and MLDSA87.is_available()

    @staticmethod
    def self_test() -> bool:
        """Run a minimal runtime test across KEM and signature primitives."""
        if not PQCKeyManager.is_available():
            return False
        try:
            kem_public, kem_private = PQCKeyManager.generate_kyber_keypair()
            ciphertext, shared_secret_1 = PQCKeyManager.encapsulate(kem_public)
            shared_secret_2 = PQCKeyManager.decapsulate(ciphertext, kem_private)
            if shared_secret_1 != shared_secret_2:
                return False

            sig_public, sig_private = PQCKeyManager.generate_dilithium_keypair()
            message = "pqc-self-test"
            signature = PQCKeyManager.sign(message, sig_private, sig_public)
            return PQCKeyManager.verify(message, signature, sig_public)
        except Exception as exc:
            logger.error("PQC self-test failed: %s", exc)
            return False

    @staticmethod
    def generate_kyber_keypair() -> Tuple[str, str]:
        kp = MLKEM1024.generate_keypair()
        return kp.public_key, kp.private_key

    @staticmethod
    def generate_dilithium_keypair() -> Tuple[str, str]:
        kp = MLDSA87.generate_keypair()
        return kp.public_key, kp.private_key

    @staticmethod
    def encapsulate(public_key: str) -> Tuple[str, str]:
        result = MLKEM1024.encapsulate(public_key)
        return result.ciphertext, result.shared_secret

    @staticmethod
    def decapsulate(ciphertext: str, private_key: str) -> str:
        return MLKEM1024.decapsulate(ciphertext, private_key)

    @staticmethod
    def sign(message: str, private_key: str, public_key: str) -> str:
        del public_key  # retained for compatibility with existing call sites
        return MLDSA87.sign(message.encode("utf-8"), private_key)

    @staticmethod
    def verify(message: str, signature: str, public_key: str) -> bool:
        return MLDSA87.verify(message.encode("utf-8"), signature, public_key)

    @staticmethod
    def get_algorithm_info() -> Dict[str, object]:
        info: Dict[str, object] = {
            "kem_algorithm": MLKEM1024.ALGORITHM,
            "sig_algorithm": MLDSA87.ALGORITHM,
            "kem_security_level": "NIST Level 5",
            "sig_security_level": "NIST Level 5",
            "kem_public_key_size": 1568,
            "kem_private_key_size": 3168,
            "kem_ciphertext_size": 1568,
            "kem_shared_secret_size": 32,
            "sig_public_key_size": 2592,
            "sig_private_key_size": 4896,
            "sig_signature_size": 4595,
            "available": PQCKeyManager.is_available(),
            "self_test_passed": PQCKeyManager.self_test(),
        }
        if LIBOQS_AVAILABLE:
            info["liboqs_version"] = oqs_version()
            info["liboqs_python_version"] = oqs_python_version()
        else:
            info["error"] = LIBOQS_ERROR
        return info
