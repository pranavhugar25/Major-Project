"""
Authentication routes for registration, login, refresh, and logout.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import re
import secrets
import time
import uuid
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, current_app, jsonify, request

from models.database import User, db
from utils.audit import log_security_event
from utils.auth import (
    JWTAuth,
    add_to_blacklist,
    get_refresh_token_from_request,
    require_auth,
    verify_refresh_token,
)

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+-]{3,255}$")

# Brute-force protections.
MAX_FAILED_ATTEMPTS = 10
LOCKOUT_DURATION_SECONDS = 15 * 60
ATTEMPT_WINDOW_SECONDS = 15 * 60
MAX_TRACKED_ATTEMPTS = 5000
LOGIN_CHALLENGE_TTL_SECONDS = 120
MAX_TRACKED_CHALLENGES = 5000

# key: "<ip>:<username-lower>"
failed_login_attempts: Dict[str, Dict[str, float]] = {}
login_challenges: Dict[str, Dict[str, str | float]] = {}

AUTH_VERIFIER_ENC_PREFIX = "encv1"
AUTH_VERIFIER_ENC_CONTEXT = b"auth-verifier-storage-v1"
AUTH_PROTOCOL_MAIN = (os.environ.get("AUTH_PROTOCOL_MAIN", "split-verifier") or "split-verifier").strip()


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _attempt_key(username: str, ip_addr: str) -> str:
    return f"{ip_addr}:{username.lower()}"


def _cleanup_failed_attempts(now: float) -> None:
    stale_keys = []
    for key, state in failed_login_attempts.items():
        locked_until = state.get("locked_until", 0.0)
        first_failed_at = state.get("first_failed_at", 0.0)
        if now > locked_until and now - first_failed_at > ATTEMPT_WINDOW_SECONDS:
            stale_keys.append(key)
    for key in stale_keys:
        failed_login_attempts.pop(key, None)

    if len(failed_login_attempts) > MAX_TRACKED_ATTEMPTS:
        sorted_items = sorted(
            failed_login_attempts.items(),
            key=lambda item: item[1].get("first_failed_at", 0.0),
        )
        remove_count = len(failed_login_attempts) - MAX_TRACKED_ATTEMPTS
        for key, _state in sorted_items[:remove_count]:
            failed_login_attempts.pop(key, None)


def _is_locked(attempt_key: str, now: float) -> int:
    state = failed_login_attempts.get(attempt_key)
    if not state:
        return 0
    locked_until = int(state.get("locked_until", 0))
    remaining = locked_until - int(now)
    return max(0, remaining)


def _record_failed_attempt(attempt_key: str, now: float) -> Dict[str, float]:
    state = failed_login_attempts.get(
        attempt_key,
        {"count": 0.0, "first_failed_at": now, "locked_until": 0.0},
    )
    if now - state["first_failed_at"] > ATTEMPT_WINDOW_SECONDS:
        state = {"count": 0.0, "first_failed_at": now, "locked_until": 0.0}

    state["count"] += 1.0
    if state["count"] >= float(MAX_FAILED_ATTEMPTS):
        state["locked_until"] = now + LOCKOUT_DURATION_SECONDS

    failed_login_attempts[attempt_key] = state
    return state


def _clear_failed_attempts(attempt_key: str) -> None:
    failed_login_attempts.pop(attempt_key, None)


def _validate_username(username: str) -> bool:
    if not username or len(username) > 255:
        return False
    return bool(USERNAME_PATTERN.fullmatch(username.strip()))


def _decode_base64_field(value: str, field_name: str) -> bytes:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} is required")
    try:
        return base64.b64decode(value.encode("utf-8"), validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc


def _validate_verifier_length(verifier_bytes: bytes) -> None:
    if len(verifier_bytes) != 32:
        raise ValueError("Password verifier must be 32 bytes")


def _derive_auth_storage_key() -> bytes:
    secret_key = str(current_app.config.get("SECRET_KEY") or "").encode("utf-8")
    if len(secret_key) < 16:
        raise ValueError("Server secret key is not configured securely")
    return hashlib.sha256(AUTH_VERIFIER_ENC_CONTEXT + secret_key).digest()


def _encrypt_auth_verifier(verifier_b64: str) -> str:
    verifier_bytes = _decode_base64_field(verifier_b64, "Password verifier")
    _validate_verifier_length(verifier_bytes)

    iv = secrets.token_bytes(12)
    ciphertext = AESGCM(_derive_auth_storage_key()).encrypt(iv, verifier_b64.encode("utf-8"), None)
    return (
        f"{AUTH_VERIFIER_ENC_PREFIX}$"
        f"{base64.b64encode(iv).decode('utf-8')}$"
        f"{base64.b64encode(ciphertext).decode('utf-8')}"
    )


def _load_auth_verifier(stored_value: str) -> str:
    if not isinstance(stored_value, str) or not stored_value.strip():
        raise ValueError("Stored verifier is missing")

    if not stored_value.startswith(f"{AUTH_VERIFIER_ENC_PREFIX}$"):
        raise ValueError("Stored verifier format is invalid")

    try:
        _prefix, iv_b64, ciphertext_b64 = stored_value.split("$", 2)
    except ValueError as exc:
        raise ValueError("Stored verifier format is invalid") from exc

    iv = _decode_base64_field(iv_b64, "Stored verifier IV")
    ciphertext = _decode_base64_field(ciphertext_b64, "Stored verifier ciphertext")
    try:
        decrypted = AESGCM(_derive_auth_storage_key()).decrypt(iv, ciphertext, None)
        verifier_b64 = decrypted.decode("utf-8")
    except Exception as exc:
        raise ValueError("Stored verifier cannot be decrypted") from exc

    verifier_bytes = _decode_base64_field(verifier_b64, "Stored verifier")
    _validate_verifier_length(verifier_bytes)
    return verifier_b64


def _validate_registration_fields(salt: str, password_verifier: str) -> str:
    try:
        salt_bytes = _decode_base64_field(salt, "Salt")
        verifier_bytes = _decode_base64_field(password_verifier, "Password verifier")
    except ValueError as exc:
        return str(exc)

    if len(salt_bytes) < 16:
        return "Salt must be at least 16 bytes"
    if len(verifier_bytes) != 32:
        return "Password verifier must be 32 bytes"
    return ""


def _cleanup_login_challenges(now: float) -> None:
    stale_ids = []
    for challenge_id, state in login_challenges.items():
        if float(state.get("expires_at", 0.0)) <= now:
            stale_ids.append(challenge_id)
    for challenge_id in stale_ids:
        login_challenges.pop(challenge_id, None)

    if len(login_challenges) > MAX_TRACKED_CHALLENGES:
        sorted_items = sorted(
            login_challenges.items(),
            key=lambda item: float(item[1].get("expires_at", 0.0)),
        )
        remove_count = len(login_challenges) - MAX_TRACKED_CHALLENGES
        for challenge_id, _state in sorted_items[:remove_count]:
            login_challenges.pop(challenge_id, None)


def _create_login_challenge(username: str, ip_addr: str, salt: str, now: float) -> Dict[str, object]:
    challenge_id = str(uuid.uuid4())
    challenge = base64.b64encode(secrets.token_bytes(32)).decode("utf-8")
    login_challenges[challenge_id] = {
        "username": username.lower(),
        "ip": ip_addr,
        "challenge": challenge,
        "expires_at": now + LOGIN_CHALLENGE_TTL_SECONDS,
    }
    return {
        "challengeId": challenge_id,
        "challenge": challenge,
        "salt": salt,
        "expiresIn": LOGIN_CHALLENGE_TTL_SECONDS,
    }


def _consume_login_challenge(challenge_id: str, username: str, ip_addr: str, now: float) -> str | None:
    state = login_challenges.pop(challenge_id, None)
    if not state:
        return None
    if float(state.get("expires_at", 0.0)) <= now:
        return None
    if str(state.get("username", "")).lower() != username.lower():
        return None
    if str(state.get("ip", "")) != ip_addr:
        return None
    return str(state.get("challenge", ""))


def _compute_expected_challenge_response(stored_verifier_b64: str, challenge_b64: str) -> str:
    verifier_bytes = _decode_base64_field(stored_verifier_b64, "Stored verifier")
    challenge_bytes = _decode_base64_field(challenge_b64, "Challenge")
    digest = hmac.new(verifier_bytes, challenge_bytes, hashlib.sha256).digest()
    return base64.b64encode(digest).decode("utf-8")


def _validate_requested_auth_protocol(data: Dict[str, object]) -> str | None:
    requested = str(data.get("authProtocol") or "").strip()
    if requested and requested != AUTH_PROTOCOL_MAIN:
        return (
            f"Unsupported auth protocol for main flow. "
            f"Configured protocol: {AUTH_PROTOCOL_MAIN}"
        )
    return None


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(silent=True) or {}
        protocol_error = _validate_requested_auth_protocol(data)
        if protocol_error:
            return jsonify({"success": False, "error": protocol_error}), 400
        username = (data.get("username") or "").strip()
        password_verifier = (data.get("passwordVerifier") or "").strip()
        salt = (data.get("salt") or "").strip()
        ip_addr = _client_ip()

        if not _validate_username(username):
            return jsonify({"success": False, "error": "Invalid username format"}), 400

        if data.get("masterPassword"):
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Plaintext master password submission is not supported",
                    }
                ),
                400,
            )

        field_error = _validate_registration_fields(salt, password_verifier)
        if field_error:
            return jsonify({"success": False, "error": field_error}), 400

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            log_security_event(
                "register",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={"reason": "duplicate_username"},
            )
            return jsonify({"success": False, "error": "Username already exists"}), 409

        new_user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            master_password_hash=_encrypt_auth_verifier(password_verifier),
            salt=salt,
        )
        db.session.add(new_user)
        db.session.commit()

        log_security_event(
            "register",
            success=True,
            user_id=str(new_user.user_id),
            username=username,
            ip_address=ip_addr,
            details={"auth_protocol": AUTH_PROTOCOL_MAIN},
        )

        return (
            jsonify(
                {
                    "success": True,
                    "message": "User registered successfully",
                    "userId": str(new_user.user_id),
                    "salt": salt,
                    "username": username,
                    "authProtocol": AUTH_PROTOCOL_MAIN,
                }
            ),
            201,
        )
    except Exception:
        db.session.rollback()
        logger.exception("Registration failed")
        return jsonify({"success": False, "error": "Registration failed. Please try again."}), 500


@auth_bp.route("/login/challenge", methods=["POST"])
def login_challenge():
    try:
        data = request.get_json(silent=True) or {}
        protocol_error = _validate_requested_auth_protocol(data)
        if protocol_error:
            return jsonify({"success": False, "error": protocol_error}), 400
        username = (data.get("username") or "").strip()
        ip_addr = _client_ip()
        now = time.time()

        if not _validate_username(username):
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        attempt_key = _attempt_key(username, ip_addr)
        _cleanup_failed_attempts(now)
        _cleanup_login_challenges(now)

        lock_remaining = _is_locked(attempt_key, now)
        if lock_remaining > 0:
            log_security_event(
                "login_challenge_blocked",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={"retry_after_seconds": lock_remaining},
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Account temporarily locked due to too many failed attempts",
                        "retry_after": lock_remaining,
                    }
                ),
                429,
            )

        user = User.query.filter_by(username=username).first()
        if not user:
            log_security_event(
                "login_challenge",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={"reason": "unknown_user"},
            )
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        challenge = _create_login_challenge(username, ip_addr, user.salt, now)
        log_security_event(
            "login_challenge",
            success=True,
            user_id=str(user.user_id),
            username=username,
            ip_address=ip_addr,
        )
        return jsonify({"success": True, **challenge, "authProtocol": AUTH_PROTOCOL_MAIN}), 200
    except Exception:
        logger.exception("Login challenge failed")
        return jsonify({"success": False, "error": "Login challenge failed. Please try again."}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json(silent=True) or {}
        protocol_error = _validate_requested_auth_protocol(data)
        if protocol_error:
            return jsonify({"success": False, "error": protocol_error}), 400
        username = (data.get("username") or "").strip()
        challenge_id = (data.get("challengeId") or "").strip()
        challenge_response = (data.get("challengeResponse") or "").strip()
        ip_addr = _client_ip()
        now = time.time()

        if not username or not challenge_id or not challenge_response:
            return (
                jsonify({"success": False, "error": "Username, challenge ID, and challenge response are required"}),
                400,
            )
        if not _validate_username(username):
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        attempt_key = _attempt_key(username, ip_addr)
        _cleanup_failed_attempts(now)
        _cleanup_login_challenges(now)

        lock_remaining = _is_locked(attempt_key, now)
        if lock_remaining > 0:
            log_security_event(
                "login_blocked",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={"retry_after_seconds": lock_remaining},
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Account temporarily locked due to too many failed attempts",
                        "retry_after": lock_remaining,
                    }
                ),
                429,
            )

        user = User.query.filter_by(username=username).first()
        challenge = _consume_login_challenge(challenge_id, username, ip_addr, now)
        if not user or not challenge:
            state = _record_failed_attempt(attempt_key, now)
            remaining_attempts = max(0, MAX_FAILED_ATTEMPTS - int(state["count"]))
            status_code = 429 if state.get("locked_until", 0) > now else 401

            log_security_event(
                "login",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={
                    "remaining_attempts": remaining_attempts,
                    "locked": status_code == 429,
                    "reason": "missing_or_invalid_challenge",
                },
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid username or password",
                        "remaining_attempts": remaining_attempts,
                    }
                ),
                status_code,
            )

        try:
            stored_verifier = _load_auth_verifier(user.master_password_hash)
            expected_response = _compute_expected_challenge_response(stored_verifier, challenge)
        except ValueError:
            logger.warning("Corrupt verifier/challenge data for user=%s", user.username)
            return jsonify({"success": False, "error": "Authentication data is invalid"}), 500

        if not secrets.compare_digest(expected_response, challenge_response):
            state = _record_failed_attempt(attempt_key, now)
            remaining_attempts = max(0, MAX_FAILED_ATTEMPTS - int(state["count"]))
            status_code = 429 if state.get("locked_until", 0) > now else 401

            log_security_event(
                "login",
                success=False,
                username=username,
                ip_address=ip_addr,
                details={
                    "remaining_attempts": remaining_attempts,
                    "locked": status_code == 429,
                },
            )
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Invalid username or password",
                        "remaining_attempts": remaining_attempts,
                    }
                ),
                status_code,
            )

        _clear_failed_attempts(attempt_key)
        tokens = JWTAuth.create_token_pair(str(user.user_id))

        log_security_event(
            "login",
            success=True,
            user_id=str(user.user_id),
            username=user.username,
            ip_address=ip_addr,
            details={"auth_protocol": f"challenge-response-{AUTH_PROTOCOL_MAIN}"},
        )

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Login successful",
                    "userId": str(user.user_id),
                    "salt": user.salt,
                    "username": user.username,
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "csrf_token": tokens["csrf_token"],
                    "token_type": tokens["token_type"],
                    "expires_in": tokens["expires_in"],
                    "authProtocol": AUTH_PROTOCOL_MAIN,
                }
            ),
            200,
        )
    except Exception:
        logger.exception("Login failed")
        return jsonify({"success": False, "error": "Login failed. Please try again."}), 500


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    try:
        data = request.get_json(silent=True) or {}
        refresh_token = get_refresh_token_from_request(data)
        if not refresh_token:
            return jsonify({"success": False, "error": "Refresh token is required"}), 400

        tokens = JWTAuth.refresh_access_token(refresh_token)

        return (
            jsonify(
                {
                    "success": True,
                    "access_token": tokens["access_token"],
                    "refresh_token": tokens["refresh_token"],
                    "csrf_token": tokens["csrf_token"],
                    "token_type": tokens["token_type"],
                    "expires_in": tokens["expires_in"],
                }
            ),
            200,
        )
    except Exception:
        logger.exception("Token refresh failed")
        return jsonify({"success": False, "error": "Invalid or expired refresh token"}), 401


@auth_bp.route("/verify", methods=["GET"])
@require_auth
def verify_token():
    return (
        jsonify(
            {
                "success": True,
                "valid": True,
                "userId": request.user_id,
                "expires_at": request.token_payload.get("exp"),
            }
        ),
        200,
    )


@auth_bp.route("/logout", methods=["POST"])
@require_auth
def logout():
    access_jti = request.session_jti
    access_exp = request.token_payload.get("exp") if hasattr(request, "token_payload") else None
    if access_jti:
        add_to_blacklist(access_jti, access_exp)

    refresh_payload = request.get_json(silent=True) or {}
    refresh_token = get_refresh_token_from_request(refresh_payload)
    if refresh_token:
        try:
            decoded_refresh = verify_refresh_token(refresh_token)
            add_to_blacklist(decoded_refresh.get("jti", ""), decoded_refresh.get("exp"))
        except Exception:
            pass

    log_security_event(
        "logout",
        success=True,
        user_id=str(request.user_id),
        ip_address=_client_ip(),
    )

    return jsonify({"success": True, "message": "Logged out successfully"}), 200
