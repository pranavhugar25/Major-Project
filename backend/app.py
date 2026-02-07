"""
Main Flask application for PQC Password Manager
Zero-Knowledge Architecture with Post-Quantum Cryptography
"""
from flask import Flask, jsonify
from flask_cors import CORS
from models.database import db
from routes.auth import auth_bp
from routes.passwords import passwords_bp
import os
from datetime import timedelta

def create_app():
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'sqlite:///pqc_password_manager.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = False
    
    # Enable CORS for frontend communication
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Initialize database
    db.init_app(app)
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    
    # Create tables
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully")
    
    # Health check endpoint
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Health check endpoint"""
        return jsonify({
            'status': 'healthy',
            'service': 'PQC Password Manager',
            'version': '1.0.0'
        }), 200
    
    # Root endpoint
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
                    'check_username': '/api/auth/check-username',
                    'get_salt': '/api/auth/get-salt'
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
                'Client-side encryption (AES-256-GCM)',
                'Post-Quantum Cryptography (ML-KEM, ML-DSA)',
                'PBKDF2 key derivation (600k iterations)',
                'Unique salt per user'
            ]
        }), 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'success': False,
            'error': 'Endpoint not found'
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
    
    return app


if __name__ == '__main__':
    app = create_app()
    
    print("\n" + "="*60)
    print("🔒 PQC Password Manager Backend Server")
    print("="*60)
    print("📡 Server running on: http://localhost:5000")
    print("🔐 Zero-Knowledge Architecture: ✓")
    print("🛡️  Post-Quantum Security: ✓")
    print("="*60 + "\n")
    
    # Run the app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
