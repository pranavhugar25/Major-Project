"""
Password management routes for encrypted credential storage.
"""
from __future__ import annotations

import base64
import logging
import uuid
from urllib.parse import urlparse

from flask import Blueprint, jsonify, request

from models.database import Password, User, db
from utils.audit import log_security_event
from utils.auth import require_auth

logger = logging.getLogger(__name__)

passwords_bp = Blueprint("passwords", __name__, url_prefix="/api/passwords")

MAX_SITE_URL_LENGTH = 512
MAX_SITE_USERNAME_LENGTH = 255
MAX_ENCRYPTED_FIELD_LENGTH = 16384


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def validate_site_url(site_url: str) -> str:
    if not isinstance(site_url, str):
        raise ValueError("Site URL must be a string")
    site_url = site_url.strip()
    if not site_url:
        raise ValueError("Site URL is required")
    if len(site_url) > MAX_SITE_URL_LENGTH:
        raise ValueError("Site URL exceeds maximum length")

    # Normalize URL if scheme was omitted by client.
    if "://" not in site_url:
        site_url = f"https://{site_url}"

    parsed = urlparse(site_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http and https URLs are allowed")
    if not parsed.netloc:
        raise ValueError("Invalid site URL")

    normalized = site_url.rstrip("/").lower()
    if len(normalized) > MAX_SITE_URL_LENGTH:
        raise ValueError("Site URL exceeds maximum length")
    return normalized


def validate_user_access(user_id_from_token: str, user_id_from_request: str | None = None) -> bool:
    if user_id_from_request is not None and user_id_from_request != user_id_from_token:
        return False
    return True


def _validate_base64_field(value: str, field_name: str, *, allow_empty: bool = False) -> str:
    if value is None:
        raise ValueError(f"{field_name} is required")
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    value = value.strip()
    if not value and allow_empty:
        return ""
    if not value:
        raise ValueError(f"{field_name} is required")
    if len(value) > MAX_ENCRYPTED_FIELD_LENGTH:
        raise ValueError(f"{field_name} exceeds maximum length")
    try:
        base64.b64decode(value.encode("utf-8"), validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} must be valid base64") from exc
    return value


@passwords_bp.route("/add", methods=["POST"])
@require_auth
def add_password():
    try:
        data = request.get_json(silent=True) or {}
        user_id_from_request = data.get("userId")
        user_id_from_token = request.user_id
        ip_addr = _client_ip()

        if not validate_user_access(user_id_from_token, user_id_from_request):
            return jsonify({"success": False, "error": "Unauthorized: Token does not match user ID"}), 403

        site_url = validate_site_url(data.get("siteUrl"))
        site_username = (data.get("siteUsername") or "").strip()
        if not site_username:
            return jsonify({"success": False, "error": "Site username is required"}), 400
        if len(site_username) > MAX_SITE_USERNAME_LENGTH:
            return jsonify({"success": False, "error": "Site username too long"}), 400

        encrypted_password = _validate_base64_field(data.get("encryptedPassword"), "Encrypted password")
        iv = _validate_base64_field(data.get("iv"), "IV")
        auth_tag = _validate_base64_field(data.get("authTag"), "Auth tag", allow_empty=True)

        user = User.query.filter_by(user_id=user_id_from_token).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        existing_password = Password.query.filter_by(user_id=user.user_id, site_url=site_url).first()
        if existing_password:
            existing_password.site_username = site_username
            existing_password.encrypted_password = encrypted_password
            existing_password.iv = iv
            existing_password.auth_tag = auth_tag
            db.session.commit()

            log_security_event(
                "password_update",
                success=True,
                user_id=user_id_from_token,
                ip_address=ip_addr,
                details={"password_id": str(existing_password.password_id), "site_url": site_url},
            )
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Password updated successfully",
                        "passwordId": str(existing_password.password_id),
                    }
                ),
                200,
            )

        new_password = Password(
            password_id=str(uuid.uuid4()),
            user_id=user.user_id,
            site_url=site_url,
            site_username=site_username,
            encrypted_password=encrypted_password,
            iv=iv,
            auth_tag=auth_tag,
        )
        db.session.add(new_password)
        db.session.commit()

        log_security_event(
            "password_add",
            success=True,
            user_id=user_id_from_token,
            ip_address=ip_addr,
            details={"password_id": str(new_password.password_id), "site_url": site_url},
        )
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Password saved successfully",
                    "passwordId": str(new_password.password_id),
                }
            ),
            201,
        )
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except Exception:
        db.session.rollback()
        logger.exception("Failed to save password")
        return jsonify({"success": False, "error": "Failed to save password. Please try again."}), 500


@passwords_bp.route("/get-all", methods=["POST"])
@require_auth
def get_all_passwords():
    try:
        user_id_from_token = request.user_id
        data = request.get_json(silent=True) or {}
        user_id_from_request = data.get("userId")
        if not validate_user_access(user_id_from_token, user_id_from_request):
            return jsonify({"success": False, "error": "Unauthorized: Token does not match user ID"}), 403

        user = User.query.filter_by(user_id=user_id_from_token).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        passwords = Password.query.filter_by(user_id=user.user_id).all()
        passwords_list = [pwd.to_dict() for pwd in passwords]

        log_security_event(
            "password_list",
            success=True,
            user_id=user_id_from_token,
            ip_address=_client_ip(),
            details={"count": len(passwords_list)},
        )
        return jsonify({"success": True, "passwords": passwords_list}), 200
    except Exception:
        logger.exception("Failed to retrieve passwords")
        return jsonify({"success": False, "error": "Failed to retrieve passwords. Please try again."}), 500


@passwords_bp.route("/delete", methods=["POST"])
@require_auth
def delete_password():
    try:
        data = request.get_json(silent=True) or {}
        password_id = (data.get("passwordId") or "").strip()
        if not password_id:
            return jsonify({"success": False, "error": "Password ID is required"}), 400

        user_id_from_token = request.user_id
        user = User.query.filter_by(user_id=user_id_from_token).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        password = Password.query.filter_by(password_id=password_id, user_id=user.user_id).first()
        if not password:
            return jsonify({"success": False, "error": "Password not found"}), 404

        db.session.delete(password)
        db.session.commit()

        log_security_event(
            "password_delete",
            success=True,
            user_id=user_id_from_token,
            ip_address=_client_ip(),
            details={"password_id": password_id, "site_url": password.site_url},
        )
        return jsonify({"success": True, "message": "Password deleted successfully"}), 200
    except Exception:
        db.session.rollback()
        logger.exception("Failed to delete password")
        return jsonify({"success": False, "error": "Failed to delete password. Please try again."}), 500


@passwords_bp.route("/get-crypto-view", methods=["POST"])
@require_auth
def get_crypto_view():
    try:
        user_id_str = request.user_id
        user = User.query.filter_by(user_id=user_id_str).first()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        passwords = Password.query.filter_by(user_id=user.user_id).all()
        encrypted_data = [
            {
                "passwordId": str(pwd.password_id),
                "siteUrl": pwd.site_url,
                "siteUsername": pwd.site_username,
                "encryptedPassword": pwd.encrypted_password,
                "iv": pwd.iv,
                "authTag": pwd.auth_tag or "",
                "note": "AES-256-GCM encrypted data",
                "createdAt": pwd.created_at.isoformat(),
                "updatedAt": pwd.updated_at.isoformat(),
            }
            for pwd in passwords
        ]

        return (
            jsonify(
                {
                    "success": True,
                    "username": user.username,
                    "userId": str(user.user_id),
                    "salt": user.salt,
                    "masterPasswordHash": "REDACTED",
                    "passwords": encrypted_data,
                    "total_entries": len(encrypted_data),
                }
            ),
            200,
        )
    except Exception:
        logger.exception("Failed to get crypto view")
        return jsonify({"success": False, "error": "Failed to retrieve crypto view. Please try again."}), 500
