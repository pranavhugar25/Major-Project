"""
Main Flask application for PQC Password Manager
Zero-Knowledge Architecture with Post-Quantum Cryptography
"""
import logging
import sys
from flask import Flask, jsonify
from flask_cors import CORS
from models.database import db
from routes.auth import auth_bp
from routes.passwords import passwords_bp
from routes.benchmark import benchmark_bp
from routes.pqc_session import pqc_session_bp
import os
from datetime import timedelta

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def create_app():
    """Application factory pattern"""
    logger.info("[APP] Creating Flask application...")
    app = Flask(__name__)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL',
        'sqlite:///pqc_password_manager.db'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ECHO'] = False
    
    logger.info(f"[APP] Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
    logger.info(f"[APP] SECRET_KEY set: {'Yes' if app.config['SECRET_KEY'] else 'No'}")
    
    # Enable CORS for frontend communication
    CORS(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    logger.info("[APP] CORS configured for localhost:3000")
    
    # Initialize database
    db.init_app(app)
    logger.info("[APP] Database initialized")
    
    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(passwords_bp)
    app.register_blueprint(benchmark_bp)
    app.register_blueprint(pqc_session_bp)
    logger.info("[APP] Blueprints registered: auth, passwords, benchmark, pqc_session")
    
    # Create tables
    with app.app_context():
        db.create_all()
        logger.info("✅ Database tables created successfully")
    
    # Initialize server signing keypair if PQC available
    from utils.pqc import LIBOQS_AVAILABLE, init_server_signing_keypair
    if LIBOQS_AVAILABLE:
        init_server_signing_keypair()
        logger.info("[APP] ML-DSA-87 server signing keypair initialized")
    else:
        logger.warning("[APP] Skipping ML-DSA initialization - PQC not available")
    
    return app


if __name__ == '__main__':
    app = create_app()
    
    # Log PQC status at startup
    from utils.pqc import PQCKeyManager, LIBOQS_AVAILABLE
    pqc_status = "✅ AVAILABLE" if LIBOQS_AVAILABLE else "❌ NOT AVAILABLE"
    logger.info(f"[APP] PQC Status: {pqc_status}")
    
    if LIBOQS_AVAILABLE:
        try:
            import oqs
            logger.info(f"[APP] liboqs module location: {oqs.__file__}")
            lib_path = os.path.dirname(oqs.__file__) if oqs.__file__ else "unknown"
            print(f"\n{'='*60}")
            print("🔒 PQC Password Manager Backend Server")
            print("="*60)
            print(f"📡 Server running on: http://localhost:5000")
            print(f"🔐 Zero-Knowledge Architecture: ✓")
            print(f"🛡️  Post-Quantum Security: {pqc_status}")
            print(f"📦 liboqs location: {lib_path}")
            print("="*60 + "\n")
        except Exception as e:
            logger.error(f"[APP] Failed to import oqs module details: {e}")
            print(f"\n{'='*60}")
            print("🔒 PQC Password Manager Backend Server")
            print("="*60)
            print(f"📡 Server running on: http://localhost:5000")
            print(f"🔐 Zero-Knowledge Architecture: ✓")
            print(f"🛡️  Post-Quantum Security: {pqc_status}")
            print("="*60 + "\n")
    else:
        print(f"\n{'='*60}")
        print("🔒 PQC Password Manager Backend Server")
        print("="*60)
        print(f"📡 Server running on: http://localhost:5000")
        print(f"🔐 Zero-Knowledge Architecture: ✓")
        print(f"🛡️  Post-Quantum Security: {pqc_status} - PQC features disabled")
        print("="*60 + "\n")
    
    # Run the app
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )
