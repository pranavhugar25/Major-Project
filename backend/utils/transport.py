"""
Hybrid PQC transport session helpers.

This provides application-layer transport protection on top of TLS:
- Hybrid key agreement: ML-KEM-1024 (PQC) + ECDH P-256 (classical)
- KDF: HKDF-SHA256 to derive a 256-bit session key
- Payload protection: AES-256-GCM
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import time
import uuid
from typing import Any, Dict, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import current_app

from utils.crypto import kyber_encapsulate

TRANSPORT_SESSION_TTL_SECONDS = 15 * 60
MAX_TRACKED_TRANSPORT_SESSIONS = 10000
HYBRID_KDF_INFO = b"pqc-hybrid-transport-v1"
CLASSICAL_KDF_INFO = b"classical-ecdh-transport-v1"

TRANSPORT_PROTOCOL_HYBRID_PQC = "hybrid_pqc"
TRANSPORT_PROTOCOL_CLASSICAL_ECDH = "classical_ecdh"
SUPPORTED_TRANSPORT_PROTOCOLS = {
    TRANSPORT_PROTOCOL_HYBRID_PQC,
    TRANSPORT_PROTOCOL_CLASSICAL_ECDH,
}
DEFAULT_TRANSPORT_PROTOCOL = (
    os.environ.get("TRANSPORT_PROTOCOL_MAIN", TRANSPORT_PROTOCOL_HYBRID_PQC)
    or TRANSPORT_PROTOCOL_HYBRID_PQC
).strip()


class TransportError(Exception):
    """Raised when transport session or envelope handling fails."""

    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


transport_sessions: Dict[str, Dict[str, Any]] = {}


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(data: str, *, field_name: str) -> bytes:
    if not isinstance(data, str) or not data.strip():
        raise TransportError(f"{field_name} is required", 400)
    try:
        return base64.b64decode(data.encode("utf-8"), validate=True)
    except Exception as exc:
        raise TransportError(f"{field_name} must be valid base64", 400) from exc


def _derive_hybrid_session_key(pqc_shared_secret: bytes, ecdh_shared_secret: bytes) -> bytes:
    if not pqc_shared_secret or not ecdh_shared_secret:
        raise TransportError("Hybrid key agreement failed", 500)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=HYBRID_KDF_INFO,
    )
    return hkdf.derive(pqc_shared_secret + ecdh_shared_secret)


def _derive_classical_session_key(ecdh_shared_secret: bytes) -> bytes:
    if not ecdh_shared_secret:
        raise TransportError("Classical key agreement failed", 500)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=CLASSICAL_KDF_INFO,
    )
    return hkdf.derive(ecdh_shared_secret)


def _cleanup_transport_sessions(now: float) -> None:
    expired_ids = [
        session_id
        for session_id, state in transport_sessions.items()
        if float(state.get("expires_at", 0.0)) <= now
    ]
    for session_id in expired_ids:
        transport_sessions.pop(session_id, None)

    if len(transport_sessions) > MAX_TRACKED_TRANSPORT_SESSIONS:
        sorted_items = sorted(
            transport_sessions.items(),
            key=lambda item: float(item[1].get("expires_at", 0.0)),
        )
        remove_count = len(transport_sessions) - MAX_TRACKED_TRANSPORT_SESSIONS
        for session_id, _state in sorted_items[:remove_count]:
            transport_sessions.pop(session_id, None)


def _validate_pqc_available() -> None:
    status = current_app.config.get("PQC_STATUS", {})
    if not bool(status.get("available")):
        raise TransportError("PQC transport is currently unavailable", 503)


def normalize_transport_protocol(protocol: str | None) -> str:
    selected = (protocol or DEFAULT_TRANSPORT_PROTOCOL).strip()
    if selected not in SUPPORTED_TRANSPORT_PROTOCOLS:
        raise TransportError(f"Unsupported transport protocol: {selected}", 400)
    return selected


def create_transport_session(
    *,
    user_id: str,
    client_pqc_public_key_b64: str | None,
    client_ecdh_public_key_b64: str,
    protocol: str | None = None,
) -> Dict[str, Any]:
    selected_protocol = normalize_transport_protocol(protocol)
    if selected_protocol == TRANSPORT_PROTOCOL_HYBRID_PQC:
        _validate_pqc_available()

    client_ecdh_public_key_bytes = _b64d(client_ecdh_public_key_b64, field_name="Client ECDH public key")
    if len(client_ecdh_public_key_bytes) < 33:
        raise TransportError("Client ECDH public key is invalid", 400)

    try:
        client_ecdh_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(),
            client_ecdh_public_key_bytes,
        )
    except Exception as exc:
        raise TransportError("Client ECDH public key is invalid", 400) from exc

    server_ecdh_private_key = ec.generate_private_key(ec.SECP256R1())
    ecdh_shared_secret = server_ecdh_private_key.exchange(ec.ECDH(), client_ecdh_public_key)
    server_ecdh_public_key_bytes = server_ecdh_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    kem_ciphertext_b64: str | None = None
    if selected_protocol == TRANSPORT_PROTOCOL_HYBRID_PQC:
        client_pqc_public_key = (client_pqc_public_key_b64 or "").strip()
        if not client_pqc_public_key:
            raise TransportError("Client PQC public key is required", 400)
        try:
            kem_ciphertext_b64, pqc_shared_secret_b64 = kyber_encapsulate(client_pqc_public_key)
        except Exception as exc:
            raise TransportError(f"ML-KEM encapsulation failed: {exc}", 500) from exc
        pqc_shared_secret = _b64d(pqc_shared_secret_b64, field_name="PQC shared secret")
        session_key = _derive_hybrid_session_key(pqc_shared_secret, ecdh_shared_secret)
        algorithm = "ML-KEM-1024+ECDH-P256+HKDF-SHA256+AES-256-GCM"
    else:
        session_key = _derive_classical_session_key(ecdh_shared_secret)
        algorithm = "ECDH-P256+HKDF-SHA256+AES-256-GCM"

    now = time.time()
    _cleanup_transport_sessions(now)
    session_id = str(uuid.uuid4())
    transport_sessions[session_id] = {
        "user_id": str(user_id),
        "key_b64": _b64e(session_key),
        "created_at": now,
        "expires_at": now + TRANSPORT_SESSION_TTL_SECONDS,
        "algorithm": algorithm,
        "protocol": selected_protocol,
    }

    return {
        "session_id": session_id,
        "server_ecdh_public_key": _b64e(server_ecdh_public_key_bytes),
        "pqc_ciphertext": kem_ciphertext_b64,
        "expires_in": TRANSPORT_SESSION_TTL_SECONDS,
        "algorithm": algorithm,
        "protocol": selected_protocol,
    }


def _get_transport_session(session_id: str, user_id: str) -> Dict[str, Any]:
    now = time.time()
    _cleanup_transport_sessions(now)

    state = transport_sessions.get(session_id)
    if not state:
        raise TransportError("Invalid transport session", 401)
    if str(state.get("user_id")) != str(user_id):
        raise TransportError("Unauthorized transport session", 403)
    if float(state.get("expires_at", 0.0)) <= now:
        transport_sessions.pop(session_id, None)
        raise TransportError("Transport session expired", 401)
    return state


def decrypt_transport_envelope(envelope: Dict[str, Any], user_id: str) -> Tuple[Dict[str, Any], str]:
    if not isinstance(envelope, dict):
        raise TransportError("Transport envelope is required", 400)

    session_id = str(envelope.get("sessionId") or "").strip()
    iv_b64 = str(envelope.get("iv") or "").strip()
    ciphertext_b64 = str(envelope.get("ciphertext") or "").strip()
    if not session_id or not iv_b64 or not ciphertext_b64:
        raise TransportError("Transport envelope fields are required", 400)

    state = _get_transport_session(session_id, user_id)
    session_key = _b64d(str(state["key_b64"]), field_name="Transport session key")
    iv = _b64d(iv_b64, field_name="Transport IV")
    ciphertext = _b64d(ciphertext_b64, field_name="Transport ciphertext")

    try:
        plaintext = AESGCM(session_key).decrypt(iv, ciphertext, None)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise TransportError("Failed to decrypt transport payload", 400) from exc

    if not isinstance(payload, dict):
        raise TransportError("Transport payload must be a JSON object", 400)
    return payload, session_id


def encrypt_transport_payload(payload: Dict[str, Any], session_id: str, user_id: str) -> Dict[str, str]:
    state = _get_transport_session(session_id, user_id)
    session_key = _b64d(str(state["key_b64"]), field_name="Transport session key")
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(session_key).encrypt(iv, plaintext, None)
    return {
        "sessionId": session_id,
        "iv": _b64e(iv),
        "ciphertext": _b64e(ciphertext),
    }


def clear_transport_sessions() -> None:
    transport_sessions.clear()
