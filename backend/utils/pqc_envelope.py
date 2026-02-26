"""
PQC envelope helpers used to make post-quantum crypto part of the active
password storage flow.

The client still performs zero-knowledge AES encryption with the vault key.
This module wraps that ciphertext in an additional server-side PQC envelope:
- ML-KEM-1024 derives a per-record symmetric key
- AES-GCM encrypts the client ciphertext payload
- ML-DSA-87 signs envelope contents for integrity/authenticity
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import current_app

from utils.crypto import (
    dilithium_sign,
    dilithium_verify,
    generate_dilithium_keypair,
    generate_kyber_keypair,
    kyber_decapsulate,
    kyber_encapsulate,
)


class PQCEnvelopeError(Exception):
    """Raised when PQC envelope operations fail."""


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"), validate=True)


def pqc_flow_available() -> bool:
    status = current_app.config.get("PQC_STATUS", {})
    return bool(status.get("available"))


def _derive_server_wrapping_key() -> bytes:
    secret = str(current_app.config.get("SECRET_KEY", "")).encode("utf-8")
    return hashlib.sha256(secret).digest()


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Tuple[str, str]:
    iv = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(iv, plaintext, None)
    return _b64e(iv), _b64e(encrypted)


def _aes_gcm_decrypt(key: bytes, iv_b64: str, ciphertext_b64: str) -> bytes:
    iv = _b64d(iv_b64)
    ciphertext = _b64d(ciphertext_b64)
    return AESGCM(key).decrypt(iv, ciphertext, None)


def _validate_payload(payload: Dict[str, Any]) -> Dict[str, str]:
    required_fields = ("encryptedPassword", "iv", "authTag")
    normalized: Dict[str, str] = {}
    for field in required_fields:
        value = payload.get(field)
        if not isinstance(value, str):
            raise PQCEnvelopeError(f"Missing or invalid payload field: {field}")
        normalized[field] = value.strip()
    return normalized


def create_pqc_envelope(payload: Dict[str, Any]) -> Dict[str, str]:
    """
    Create a PQC envelope for already client-encrypted password payload.

    Returns a dict suitable for PasswordPQCEnvelope columns.
    """
    if not pqc_flow_available():
        raise PQCEnvelopeError("PQC flow is not available")

    normalized_payload = _validate_payload(payload)
    payload_bytes = json.dumps(
        normalized_payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    try:
        kem_public_key, kem_private_key = generate_kyber_keypair()
        kem_ciphertext, shared_secret_b64 = kyber_encapsulate(kem_public_key)
        decapsulated_shared_secret_b64 = kyber_decapsulate(kem_ciphertext, kem_private_key)

        if not secrets.compare_digest(shared_secret_b64, decapsulated_shared_secret_b64):
            raise PQCEnvelopeError("ML-KEM shared secret mismatch")

        shared_secret = _b64d(decapsulated_shared_secret_b64)
        payload_iv, payload_ciphertext = _aes_gcm_encrypt(shared_secret, payload_bytes)

        sig_public_key, sig_private_key = generate_dilithium_keypair()
        signature_message = f"{kem_ciphertext}.{payload_iv}.{payload_ciphertext}"
        payload_signature = dilithium_sign(signature_message, sig_private_key, sig_public_key)

        wrapping_key = _derive_server_wrapping_key()
        private_key_iv, encrypted_private_key = _aes_gcm_encrypt(
            wrapping_key,
            kem_private_key.encode("utf-8"),
        )

        return {
            "kem_ciphertext": kem_ciphertext,
            "encrypted_kem_private_key": encrypted_private_key,
            "kem_private_key_iv": private_key_iv,
            "payload_ciphertext": payload_ciphertext,
            "payload_iv": payload_iv,
            "payload_signature": payload_signature,
            "signature_public_key": sig_public_key,
            "pqc_algorithm": "ML-KEM-1024+ML-DSA-87",
        }
    except PQCEnvelopeError:
        raise
    except Exception as exc:
        raise PQCEnvelopeError(f"Failed to create PQC envelope: {exc}") from exc


def open_pqc_envelope(envelope: Any) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """
    Verify and decrypt a PQC envelope row, returning the original payload.
    """
    if not pqc_flow_available():
        raise PQCEnvelopeError("PQC flow is not available")

    try:
        signature_message = (
            f"{envelope.kem_ciphertext}.{envelope.payload_iv}.{envelope.payload_ciphertext}"
        )
        signature_valid = dilithium_verify(
            signature_message,
            envelope.payload_signature,
            envelope.signature_public_key,
        )
        if not signature_valid:
            raise PQCEnvelopeError("Invalid ML-DSA envelope signature")

        wrapping_key = _derive_server_wrapping_key()
        kem_private_key = _aes_gcm_decrypt(
            wrapping_key,
            envelope.kem_private_key_iv,
            envelope.encrypted_kem_private_key,
        ).decode("utf-8")

        shared_secret_b64 = kyber_decapsulate(envelope.kem_ciphertext, kem_private_key)
        shared_secret = _b64d(shared_secret_b64)

        payload_json = _aes_gcm_decrypt(
            shared_secret,
            envelope.payload_iv,
            envelope.payload_ciphertext,
        ).decode("utf-8")

        payload = json.loads(payload_json)
        normalized_payload = _validate_payload(payload)
        return normalized_payload, {
            "active": True,
            "verified": True,
            "algorithm": envelope.pqc_algorithm,
        }
    except PQCEnvelopeError:
        raise
    except Exception as exc:
        raise PQCEnvelopeError(f"Failed to open PQC envelope: {exc}") from exc
