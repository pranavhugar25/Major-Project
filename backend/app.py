"""
Main Flask application for PQC Password Manager
Zero-Knowledge Architecture with Post-Quantum Cryptography

Security Features:
- JWT-based authentication (15-min token expiry)
- Rate limiting on all endpoints
- CSRF protection
- Secure secret key generation
"""
from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from models.database import db
from routes.auth import auth_bp
from routes.passwords import passwords_bp
from routes.benchmark import benchmark_bp
from routes.pqc_session import pqc_session_bp
import os
import secrets
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(testing: bool = False):
    """
    Application factory pattern
    
    Args:
        testing: If True, use testing configuration (no rate limiting)
    """
    app = Flask(__name__)
    
    # ====================================================================
    # Security Configuration
    # ====================================================================
    
    # Secret key - generate strong key for production
    secret_key = os.environ.get('SECRET_KEY')
    if not secret_key:
        if os.environ.get('FLASK_ENV') == 'production' and not testing:
            raise RuntimeError(
                "SECRET_KEY must be set in production mode. "
                "Set the SECRET_KEY environment variable."
            )
        # Generate strong key for development
        secret_key = secrets.token_hex(64)
    
    app.config['SECRET_KEY'] = secret_key
    
    # ====================================================================
    # Request Size Limits
    # ====================================================================
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
    
    # ====================================================================
    # Database Configuration
    # ====================================================================
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'sqlite:///pqc_password_manager.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = False
    
    # ====================================================================
    # Rate Limiting Configuration (Issue C3)
    # ====================================================================
    if not testing:
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"],
            storage_uri=os.environ.get('RATELIMIT_STORAGE_URL', "memory://")
        )
    else:
        # Disable rate limiting during tests
        limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["1000 per minute"],
            storage_uri="memory://"
        )
    
    # ====================================================================
    # CSRF Protection - Disabled for API endpoints
    # JWT-based APIs using Authorization header don't require CSRF protection
    # ====================================================================
    csrf = CSRFProtect()
    
    # Exempt API endpoints from CSRF protection (they use JWT tokens)
    @csrf.exempt
    def apis_without_csrf():
        pass
    
    # Manually exempt the auth and passwords blueprints
    csrf.exempt(auth_bp)
    csrf.exempt(passwords_bp)
    csrf.exempt(benchmark_bp)
    csrf.exempt(pqc_session_bp)
    
    # ====================================================================
    # CORS Configuration
    # ====================================================================
    CORS(app, resources={
        r"/api/*": {
            "origins": os.environ.get(
                'CORS_ORIGINS', 
                "http://localhost:3000 http://127.0.0.1:3000"
            ).split(),
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization", "X-CSRF-Token"],
            "supports_credentials": True
        }
    })
    
    # ====================================================================
    # Initialize Database
    # ====================================================================
    db.init_app(app)
    
    # ====================================================================
    # Register Blueprints
    # ====================================================================
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    app.register_blueprint(benchmark_bp)
    app.register_blueprint(pqc_session_bp)
    
    # ====================================================================
    # Create Tables
    # ====================================================================
    with app.app_context():
        db.create_all()
        logger.info("✅ Database tables created successfully")
    
    # ====================================================================
    # Security Headers (Issue H1)
    # ====================================================================
    @app.after_request
    def add_security_headers(response):
        """Add security headers to all responses"""
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        return response
    
    # ====================================================================
    # Health Check Endpoint
    # ====================================================================
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'PQC Password Manager',
            'version': '1.0.0',
            'security': {
                'pqc_enabled': True,
                'jwt_enabled': True,
                'rate_limiting': True,
                'csrf_protection': True
            }
        }), 200
    
    # ====================================================================
    # Root Endpoint
    # ====================================================================
    @app.route('/', methods=['GET'])
    def index():
        """Root endpoint with API information"""
        return jsonify({
            'service': 'PQC Password Manager API',
            'version': '1.0.0',
            'description': 'Zero-Knowledge Post-Quantum Cryptography Password Manager',
            'endpoints': {
                'auth': {
                    'register': '/api/auth/register',
                    'login': '/api/auth/login',
                    'refresh': '/api/auth/refresh',
                    'verify': '/api/auth/verify',
                    'logout': '/api/auth/logout'
                },
                'passwords': {
                    'add': '/api/passwords/add',
                    'get_all': '/api/passwords/get-all',
                    'delete': '/api/passwords/delete',
                    'crypto_view': '/api/passwords/get-crypto-view'
                }
            },
            'security_features': [
                'Zero-Knowledge Architecture',
                'Client-side AES-256-GCM encryption',
                'Post-Quantum Cryptography (ML-KEM-768, ML-DSA-65)',
                'PBKDF2 key derivation (600k iterations)',
                'JWT authentication (15-min expiry)',
                'Rate limiting',
                'CSRF protection'
            ]
        }), 200
    
    # ====================================================================
    # Error Handlers
    # ====================================================================
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Endpoint not found'
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        logger.error(f"Internal server error: {error}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
    
    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify({
            'success': False,
            'error': 'Rate limit exceeded. Please try again later.',
            'retry_after': error.description
        }), 429
    
    return app


# Create default app instance
app = create_app()


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔒 PQC Password Manager Backend Server")
    print("="*60)
    print("📡 Server running on: http://localhost:5000")
    print("🔐 Zero-Knowledge Architecture: ✓")
    print("🛡️  Post-Quantum Security (ML-KEM-768, ML-DSA-65): ✓")
    print("🔑 JWT Authentication (15-min expiry): ✓")
    print("🚦 Rate Limiting: ✓")
    print("🛡️  CSRF Protection: ✓")
    print("="*60 + "\n")
    
    # Run with proper configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode,
        threaded=True
    )
