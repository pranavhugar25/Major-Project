"""
Hybrid PQC transport session routes.
"""
from __future__ import annotations

import logging

from flask import Blueprint, jsonify, request

from utils.audit import log_security_event
from utils.auth import require_auth
from utils.transport import TransportError, create_transport_session

logger = logging.getLogger(__name__)

transport_bp = Blueprint("transport", __name__, url_prefix="/api/transport")


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


@transport_bp.route("/init", methods=["POST"])
@require_auth
def init_transport_session():
    try:
        data = request.get_json(silent=True) or {}
        client_pqc_public_key = (data.get("clientPqcPublicKey") or "").strip()
        client_ecdh_public_key = (data.get("clientEcdhPublicKey") or "").strip()
        if not client_pqc_public_key or not client_ecdh_public_key:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Client PQC and ECDH public keys are required",
                    }
                ),
                400,
            )

        result = create_transport_session(
            user_id=str(request.user_id),
            client_pqc_public_key_b64=client_pqc_public_key,
            client_ecdh_public_key_b64=client_ecdh_public_key,
        )

        log_security_event(
            "transport_init",
            success=True,
            user_id=str(request.user_id),
            ip_address=_client_ip(),
            details={"algorithm": result["algorithm"], "expires_in": result["expires_in"]},
        )

        return (
            jsonify(
                {
                    "success": True,
                    "sessionId": result["session_id"],
                    "serverEcdhPublicKey": result["server_ecdh_public_key"],
                    "pqcCiphertext": result["pqc_ciphertext"],
                    "expiresIn": result["expires_in"],
                    "algorithm": result["algorithm"],
                }
            ),
            200,
        )
    except TransportError as exc:
        return jsonify({"success": False, "error": exc.message}), exc.status_code
    except Exception:
        logger.exception("Failed to initialize hybrid transport session")
        return jsonify({"success": False, "error": "Failed to initialize secure transport session"}), 500
