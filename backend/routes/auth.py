"""
Authentication routes for registration, login, refresh, and logout.
"""
from __future__ import annotations

import logging
import re
import time
import uuid
from typing import Dict

from flask import Blueprint, jsonify, request

from models.database import User, db
from utils.audit import log_security_event
from utils.auth import (
    JWTAuth,
    add_to_blacklist,
    get_refresh_token_from_request,
    require_auth,
    verify_refresh_token,
)
from utils.crypto import generate_salt, hash_password, verify_password

logger = logging.getLogger(__name__)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9._@+-]{3,255}$")
MAX_MASTER_PASSWORD_LENGTH = 1024

# Brute-force protections.
MAX_FAILED_ATTEMPTS = 10
LOCKOUT_DURATION_SECONDS = 15 * 60
ATTEMPT_WINDOW_SECONDS = 15 * 60
MAX_TRACKED_ATTEMPTS = 5000

# key: "<ip>:<username-lower>"
failed_login_attempts: Dict[str, Dict[str, float]] = {}


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


def _validate_master_password(master_password: str) -> str:
    if not master_password:
        return "Master password is required"
    if len(master_password) < 12:
        return "Password must be at least 12 characters"
    if len(master_password) > MAX_MASTER_PASSWORD_LENGTH:
        return "Password is too long"

    has_uppercase = any(char.isupper() for char in master_password)
    has_lowercase = any(char.islower() for char in master_password)
    has_digit = any(char.isdigit() for char in master_password)
    has_special = any(not char.isalnum() for char in master_password)
    if not (has_uppercase and has_lowercase and has_digit and has_special):
        return "Password must contain uppercase, lowercase, number, and special character"
    return ""


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        master_password = data.get("masterPassword") or ""
        ip_addr = _client_ip()

        if not _validate_username(username):
            return jsonify({"success": False, "error": "Invalid username format"}), 400

        password_error = _validate_master_password(master_password)
        if password_error:
            return jsonify({"success": False, "error": password_error}), 400

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

        salt = generate_salt()
        master_password_hash = hash_password(master_password, salt)
        new_user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            master_password_hash=master_password_hash,
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
        )

        return (
            jsonify(
                {
                    "success": True,
                    "message": "User registered successfully",
                    "userId": str(new_user.user_id),
                    "salt": salt,
                    "username": username,
                }
            ),
            201,
        )
    except Exception as exc:
        db.session.rollback()
        logger.exception("Registration failed")
        return jsonify({"success": False, "error": "Registration failed. Please try again."}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json(silent=True) or {}
        username = (data.get("username") or "").strip()
        master_password = data.get("masterPassword") or ""
        ip_addr = _client_ip()
        now = time.time()

        if not username or not master_password:
            return jsonify({"success": False, "error": "Username and master password are required"}), 400
        if not _validate_username(username):
            return jsonify({"success": False, "error": "Invalid username or password"}), 401

        attempt_key = _attempt_key(username, ip_addr)
        _cleanup_failed_attempts(now)

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
        if not user or not verify_password(master_password, user.salt, user.master_password_hash):
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
