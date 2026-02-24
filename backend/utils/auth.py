"""
JWT authentication utilities with CSRF protection and refresh-token rotation.
"""
from __future__ import annotations

import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Dict, Optional

import jwt
from flask import current_app, jsonify, request

TOKEN_EXPIRY_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRY_MINUTES", "15"))
REFRESH_TOKEN_EXPIRY_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRY_DAYS", "1"))

ACCESS_TOKEN_COOKIE = "pqc_access_token"
REFRESH_TOKEN_COOKIE = "pqc_refresh_token"
CSRF_HEADER = "X-CSRF-Token"

SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS"}

# In production, this should be backed by Redis or another shared datastore.
token_blacklist: Dict[str, float] = {}
_blacklist_cleanup_counter = 0
BLACKLIST_CLEANUP_INTERVAL = 10


class AuthError(Exception):
    """Authentication/authorization error."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def add_to_blacklist(jti: str, exp: Optional[Any] = None) -> None:
    global _blacklist_cleanup_counter
    if not jti:
        return
    if exp is None:
        exp = datetime.now(timezone.utc) + timedelta(days=1)
    if isinstance(exp, datetime):
        exp_timestamp = exp.timestamp()
    else:
        exp_timestamp = float(exp)
    token_blacklist[jti] = exp_timestamp
    _blacklist_cleanup_counter += 1
    if _blacklist_cleanup_counter >= BLACKLIST_CLEANUP_INTERVAL:
        cleanup_expired_tokens()
        _blacklist_cleanup_counter = 0


def is_blacklisted(jti: str) -> bool:
    cleanup_expired_tokens()
    return jti in token_blacklist


def cleanup_expired_tokens() -> int:
    now = time.time()
    expired = [jti for jti, exp in token_blacklist.items() if exp < now]
    for jti in expired:
        del token_blacklist[jti]
    return len(expired)


def clear_blacklist() -> None:
    token_blacklist.clear()


def generate_session_token(
    user_id: str,
    *,
    csrf_token: Optional[str] = None,
    additional_claims: Optional[Dict[str, Any]] = None,
) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "user_id": user_id,
        "sub": user_id,
        "exp": now + timedelta(minutes=TOKEN_EXPIRY_MINUTES),
        "iat": now,
        "type": "session",
        "jti": secrets.token_hex(16),
        "csrf": csrf_token or secrets.token_urlsafe(32),
    }
    if additional_claims:
        payload.update(additional_claims)
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def generate_refresh_token(user_id: str) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "user_id": user_id,
        "sub": user_id,
        "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
        "iat": now,
        "type": "refresh",
        "jti": secrets.token_hex(16),
    }
    return jwt.encode(payload, current_app.config["SECRET_KEY"], algorithm="HS256")


def verify_session_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("type") != "session":
            raise AuthError("Invalid token type")
        jti = payload.get("jti")
        if jti and is_blacklisted(jti):
            raise AuthError("Token has been revoked")
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Session expired", 401) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid or expired token", 401) from exc


def verify_refresh_token(token: str) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, current_app.config["SECRET_KEY"], algorithms=["HS256"])
        if payload.get("type") != "refresh":
            raise AuthError("Invalid token type")
        jti = payload.get("jti")
        if jti and is_blacklisted(jti):
            raise AuthError("Refresh token has been revoked")
        return payload
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Refresh token expired", 401) from exc
    except jwt.InvalidTokenError as exc:
        raise AuthError("Invalid or expired refresh token", 401) from exc


def get_token_from_request() -> Optional[str]:
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    cookie_token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    if cookie_token:
        return cookie_token
    return None


def get_refresh_token_from_request(payload: Optional[Dict[str, Any]] = None) -> Optional[str]:
    if payload and payload.get("refresh_token"):
        return payload.get("refresh_token")
    cookie_token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    if cookie_token:
        return cookie_token
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return None


def validate_csrf_token(payload: Dict[str, Any]) -> None:
    if request.method in SAFE_HTTP_METHODS:
        return
    expected = payload.get("csrf")
    provided = request.headers.get(CSRF_HEADER)
    if not expected or not provided:
        raise AuthError("Missing CSRF token", 403)
    if not secrets.compare_digest(str(expected), str(provided)):
        raise AuthError("Invalid CSRF token", 403)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_request()
        if not token:
            return jsonify({"success": False, "error": "Missing authentication token"}), 401
        try:
            payload = verify_session_token(token)
            validate_csrf_token(payload)
            request.user_id = payload["user_id"]
            request.session_jti = payload.get("jti")
            request.token_payload = payload
        except AuthError as exc:
            return jsonify({"success": False, "error": exc.message}), exc.status_code
        return f(*args, **kwargs)

    return decorated


class JWTAuth:
    """Class-based JWT helpers used by route handlers."""

    @staticmethod
    def create_access_token(user_id: str, *, csrf_token: Optional[str] = None) -> str:
        return generate_session_token(user_id, csrf_token=csrf_token)

    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        return generate_refresh_token(user_id)

    @staticmethod
    def create_token_pair(user_id: str) -> Dict[str, Any]:
        csrf_token = secrets.token_urlsafe(32)
        return {
            "access_token": JWTAuth.create_access_token(user_id, csrf_token=csrf_token),
            "refresh_token": JWTAuth.create_refresh_token(user_id),
            "csrf_token": csrf_token,
            "token_type": "Bearer",
            "expires_in": TOKEN_EXPIRY_MINUTES * 60,
        }

    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        return verify_session_token(token)

    @staticmethod
    def refresh_access_token(refresh_token: str) -> Dict[str, Any]:
        payload = verify_refresh_token(refresh_token)
        add_to_blacklist(payload.get("jti", ""), payload.get("exp"))
        return JWTAuth.create_token_pair(payload["user_id"])
