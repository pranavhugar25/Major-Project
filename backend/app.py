"""
Main Flask application for the PQC Password Manager backend.
"""
from __future__ import annotations

import logging
import os
import secrets
from typing import Dict, List

from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from models.database import db
from routes.auth import auth_bp
from routes.benchmark import benchmark_bp
from routes.passwords import passwords_bp
from routes.transport import transport_bp

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _parse_cors_origins() -> List[str]:
    raw = os.environ.get("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000")
    normalized = raw.replace(" ", ",")
    origins = [origin.strip() for origin in normalized.split(",") if origin.strip()]
    return origins


def _load_pqc_status() -> Dict[str, object]:
    try:
        from utils.pqc import PQCKeyManager

        available = PQCKeyManager.is_available()
        self_test_passed = PQCKeyManager.self_test() if available else False
        info = PQCKeyManager.get_algorithm_info()
        return {
            "available": available and self_test_passed,
            "self_test_passed": self_test_passed,
            "algorithms": info,
        }
    except Exception as exc:
        logger.exception("PQC initialization failed")
        return {
            "available": False,
            "self_test_passed": False,
            "error": str(exc),
            "algorithms": {},
        }


def _apply_endpoint_rate_limits(app: Flask, limiter: Limiter) -> None:
    endpoint_limits = {
        "auth.register": "3 per 15 minute",
        "auth.login_challenge": "20 per 15 minute",
        "auth.login": "5 per 15 minute",
        "auth.refresh": "10 per 15 minute",
        "auth.logout": "10 per 15 minute",
        "transport.init_transport_session": "30 per 15 minute",
        "benchmark.get_benchmark_protocols": "60 per hour",
        "benchmark.run_benchmarks": "20 per hour",
        "passwords.add_password": "60 per hour",
        "passwords.get_all_passwords": "120 per hour",
        "passwords.delete_password": "60 per hour",
        "passwords.get_crypto_view": "60 per hour",
    }
    for endpoint, limit in endpoint_limits.items():
        view_func = app.view_functions.get(endpoint)
        if view_func is None:
            logger.warning("Rate-limit target endpoint not found: %s", endpoint)
            continue
        app.view_functions[endpoint] = limiter.limit(limit)(view_func)


def create_app(testing: bool = False) -> Flask:
    app = Flask(__name__)

    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        if os.environ.get("FLASK_ENV") == "production" and not testing:
            raise RuntimeError("SECRET_KEY must be set in production mode.")
        secret_key = secrets.token_hex(64)
    app.config["SECRET_KEY"] = secret_key
    app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///pqc_password_manager.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = False

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": _parse_cors_origins(),
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"],
                "supports_credentials": True,
            }
        },
    )

    db.init_app(app)
    app.register_blueprint(auth_bp)
    app.register_blueprint(transport_bp)
    app.register_blueprint(benchmark_bp)
    app.register_blueprint(passwords_bp)

    limiter = Limiter(
        key_func=get_remote_address,
        default_limits=(["1000 per minute"] if testing else ["500 per day", "100 per hour"]),
        storage_uri=("memory://" if testing else os.environ.get("RATELIMIT_STORAGE_URL", "memory://")),
        headers_enabled=True,
    )
    limiter.init_app(app)
    _apply_endpoint_rate_limits(app, limiter)

    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")

    app.config["PQC_STATUS"] = _load_pqc_status()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-site"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        )
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.is_secure or os.environ.get("FLASK_ENV") == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.route("/api/health", methods=["GET"])
    def health_check():
        pqc_status = app.config.get("PQC_STATUS", {})
        return (
            jsonify(
                {
                    "status": "healthy",
                    "service": "PQC Password Manager",
                    "version": "1.0.0",
                    "security": {
                        "pqc_enabled": bool(pqc_status.get("available")),
                        "pqc_self_test_passed": bool(pqc_status.get("self_test_passed")),
                        "pqc_algorithms": pqc_status.get("algorithms", {}),
                        "jwt_enabled": True,
                        "rate_limiting": True,
                        "csrf_protection": True,
                        "hybrid_transport": True,
                        "auth_protocol_main": os.environ.get("AUTH_PROTOCOL_MAIN", "split-verifier"),
                        "transport_protocol_main": os.environ.get(
                            "TRANSPORT_PROTOCOL_MAIN",
                            "hybrid_pqc",
                        ),
                    },
                }
            ),
            200,
        )

    @app.route("/api/pqc/self-test", methods=["GET"])
    def pqc_self_test():
        status = _load_pqc_status()
        app.config["PQC_STATUS"] = status
        return jsonify({"success": True, "pqc": status}), 200

    @app.route("/", methods=["GET"])
    def index():
        pqc_status = app.config.get("PQC_STATUS", {})
        pqc_info = pqc_status.get("algorithms", {})
        return (
            jsonify(
                {
                    "service": "PQC Password Manager API",
                    "version": "1.0.0",
                    "description": "Zero-Knowledge Post-Quantum Cryptography Password Manager",
                    "pqc_status": (
                        "enabled" if pqc_status.get("available") else "disabled"
                    ),
                    "endpoints": {
                        "auth": {
                            "register": "/api/auth/register",
                            "login_challenge": "/api/auth/login/challenge",
                            "login": "/api/auth/login",
                            "refresh": "/api/auth/refresh",
                            "verify": "/api/auth/verify",
                            "logout": "/api/auth/logout",
                        },
                        "transport": {
                            "init": "/api/transport/init",
                        },
                        "benchmark": {
                            "protocols": "/api/benchmark/protocols",
                            "run": "/api/benchmark/run",
                        },
                        "passwords": {
                            "add": "/api/passwords/add",
                            "get_all": "/api/passwords/get-all",
                            "delete": "/api/passwords/delete",
                            "crypto_view": "/api/passwords/get-crypto-view",
                        },
                        "pqc": {"self_test": "/api/pqc/self-test"},
                    },
                    "security_features": [
                        "Zero-Knowledge Architecture",
                        "Client-side AES-256-GCM encryption",
                        (
                            f"Post-Quantum Cryptography: {pqc_info.get('kem_algorithm', 'N/A')}, "
                            f"{pqc_info.get('sig_algorithm', 'N/A')}"
                        ),
                        "Hybrid PQC transport sessions (ML-KEM + ECDH + AES-GCM)",
                        "PBKDF2 key derivation (600k iterations)",
                        "JWT authentication (15-minute expiry)",
                        "Rate limiting",
                        "CSRF token enforcement",
                    ],
                }
            ),
            200,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({"success": False, "error": "Endpoint not found"}), 404

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        retry_after = getattr(error, "retry_after", None)
        if retry_after is None:
            try:
                retry_after = int(getattr(error, "description", 0))
            except Exception:
                retry_after = None
        response = jsonify(
            {
                "success": False,
                "error": "Rate limit exceeded. Please try again later.",
                "retry_after": retry_after,
            }
        )
        if retry_after is not None:
            response.headers["Retry-After"] = str(int(retry_after))
        return response, 429

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        logger.exception("Internal server error: %s", error)
        return jsonify({"success": False, "error": "Internal server error"}), 500

    return app


app = create_app()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    pqc_status = app.config.get("PQC_STATUS", {})
    logger.info(
        "Starting backend on http://localhost:5000 | PQC enabled=%s",
        pqc_status.get("available"),
    )
    app.run(host="0.0.0.0", port=5000, debug=debug_mode, threaded=True)
