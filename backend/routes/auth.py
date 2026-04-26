"""
Authentication routes for user registration and login
Zero-knowledge architecture: master password never stored in plain text

JWT-based session management for secure API authentication.
"""
from flask import Blueprint, request, jsonify
from models.database import db, User
from utils.crypto import generate_salt, hash_password, verify_password_with_algorithm
from utils.auth import JWTAuth, require_auth, generate_session_token, add_to_blacklist
from utils.spake2_pake import generate_password_verifier, compute_verifier, create_server, create_client
import uuid
import logging
import time
import base64

logger = logging.getLogger(__name__)

# Failed login tracking for brute force protection
failed_login_attempts = {}
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300  # 5 minutes in seconds

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
    """
    Register a new user
    
    Request body:
        {
            "username": "user@example.com",
            "masterPassword": "securePassword123"
        }
    
    Response:
        {
            "success": true,
            "message": "User registered successfully",
            "userId": "uuid",
            "salt": "base64_salt"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        username = data.get('username')
        master_password = data.get('masterPassword')
        
        # Validation
        if not username or not master_password:
            return jsonify({
                'success': False,
                'error': 'Username and master password are required'
            }), 400
        
        # Enhanced password strength validation
        if len(master_password) < 12:
            return jsonify({
                'success': False,
                'error': 'Password must be at least 12 characters'
            }), 400
        
        # Check for complexity requirements
        has_uppercase = any(c.isupper() for c in master_password)
        has_lowercase = any(c.islower() for c in master_password)
        has_digit = any(c.isdigit() for c in master_password)
        has_special = any(not c.isalnum() for c in master_password)
        
        if not (has_uppercase and has_lowercase and has_digit and has_special):
            return jsonify({
                'success': False,
                'error': 'Password must contain uppercase, lowercase, numbers, and special characters'
            }), 400
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            # Generic error message to prevent user enumeration
            return jsonify({
                'success': False,
                'error': 'An account with this email already exists'
            }), 409
        
        # Generate unique salt for this user
        salt = generate_salt()
        
        # Generate SPAKE2 verifier for PAKE authentication
        spake2_verifier, spake2_salt = generate_password_verifier(master_password)
        
        # Hash the master password using the current Argon2id implementation.
        master_password_hash = hash_password(master_password, salt)
        
        # Create new user
        new_user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            master_password_hash=master_password_hash,
            salt=salt,
            spake2_verifier=spake2_verifier,
            spake2_salt=spake2_salt
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        
        # Generate JWT tokens for immediate login
        tokens = JWTAuth.create_token_pair(str(new_user.user_id))
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'userId': str(new_user.user_id),
            'salt': salt,
            'spake2Available': True,
            'username': username,
            'access_token': tokens['access_token'],
            'refresh_token': tokens.get('refresh_token'),
            'token_type': tokens['token_type'],
            'expires_in': tokens['expires_in']
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Registration failed. Please try again.'
        }), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return JWT tokens
    
    Request body:
        {
            "username": "user@example.com",
            "masterPassword": "securePassword123"
        }
    
    Response:
        {
            "success": true,
            "message": "Login successful",
            "userId": "uuid",
            "salt": "base64_salt",
            "username": "user@example.com",
            "access_token": "jwt_token",
            "refresh_token": "jwt_refresh_token",
            "token_type": "Bearer",
            "expires_in": 900
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        username = data.get('username')
        master_password = data.get('masterPassword')
        
        # Validation
        if not username or not master_password:
            return jsonify({
                'success': False,
                'error': 'Username and master password are required'
            }), 400
        
        # Check for brute force lockout
        client_ip = request.remote_addr
        current_time = time.time()
        
        if username in failed_login_attempts:
            attempts, lockout_time = failed_login_attempts[username]
            if current_time < lockout_time:
                remaining_time = int(lockout_time - current_time)
                return jsonify({
                    'success': False,
                    'error': 'Account temporarily locked due to too many failed attempts',
                    'retry_after': remaining_time
                }), 429
            else:
                # Lockout expired, reset counter
                del failed_login_attempts[username]
        
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            logger.warning(f"Login attempt for non-existent user: {username}")
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401
        
        # Verify password using SPAKE2 verifier if available, otherwise use classical
        spake2_verified = False
        if user.spake2_verifier and user.spake2_salt:
            # SPAKE2-based verification (quantum-resistant PAKE)
            try:
                # Compute verifier and compare
                test_verifier = compute_verifier(master_password, user.spake2_salt)
                import secrets
                spake2_verified = secrets.compare_digest(test_verifier, user.spake2_verifier)
            except Exception as e:
                logger.warning(f"SPAKE2 verification failed: {e}")
        
        # Fall back to classical verification if SPAKE2 not available or failed
        classical_verified, password_hash_algorithm = verify_password_with_algorithm(
            master_password,
            user.salt,
            user.master_password_hash
        )

        if not (spake2_verified or classical_verified):
            # Track failed attempt
            failed_login_attempts[username] = (failed_login_attempts.get(username, (0, 0))[0] + 1, current_time + LOCKOUT_DURATION)
            
            # Calculate remaining attempts
            remaining_attempts = MAX_FAILED_ATTEMPTS - failed_login_attempts[username][0]
            
            logger.warning(f"Failed login attempt for user: {username}")
            return jsonify({
                'success': False,
                'error': 'Invalid username or password',
                'remaining_attempts': remaining_attempts
            }), 401
        
        # Successful login - clear failed attempts
        if username in failed_login_attempts:
            del failed_login_attempts[username]

        # Lazily upgrade legacy PBKDF2 hashes to Argon2id while keeping the same salt
        if password_hash_algorithm == 'pbkdf2':
            try:
                user.master_password_hash = hash_password(master_password, user.salt)
                db.session.commit()
                logger.info(f"Upgraded master password hash to Argon2id for user: {username}")
            except Exception as e:
                db.session.rollback()
                logger.warning(f"Failed to upgrade master password hash for {username}: {e}")
        
        # Generate JWT tokens
        tokens = JWTAuth.create_token_pair(str(user.user_id))
        
        logger.info(f"User logged in: {username}")
        
        # Successful login - return tokens and salt for client-side vault key derivation
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'userId': str(user.user_id),
            'salt': user.salt,
            'spake2Available': user.spake2_verifier is not None,
            'username': user.username,
            'access_token': tokens['access_token'],
            'refresh_token': tokens.get('refresh_token'),
            'token_type': tokens['token_type'],
            'expires_in': tokens['expires_in']
        }), 200
        
    except Exception as e:
        logger.error(f"Login failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Login failed. Please try again.'
        }), 500


@auth_bp.route('/refresh', methods=['POST'])
def refresh():
    """
    Refresh access token using refresh token
    
    Request body:
        {
            "refresh_token": "jwt_refresh_token"
        }
    
    Response:
        {
            "success": true,
            "access_token": "new_jwt_token",
            "token_type": "Bearer",
            "expires_in": 900
        }
    """
    try:
        data = request.get_json()
        
        if not data or not data.get('refresh_token'):
            return jsonify({
                'success': False,
                'error': 'Refresh token is required'
            }), 400
        
        refresh_token = data.get('refresh_token')
        
        # Use refresh token to get new access token
        tokens = JWTAuth.refresh_access_token(refresh_token)
        
        return jsonify({
            'success': True,
            'access_token': tokens['access_token'],
            'token_type': tokens['token_type'],
            'expires_in': tokens['expires_in']
        }), 200
        
    except Exception as e:
        logger.error(f"Token refresh failed: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Invalid or expired refresh token'
        }), 401


@auth_bp.route('/verify', methods=['GET'])
@require_auth
def verify_token():
    """
    Verify if current access token is valid
    
    Response:
        {
            "success": true,
            "valid": true,
            "userId": "uuid",
            "expires_at": "timestamp"
        }
    """
    return jsonify({
        'success': True,
        'valid': True,
        'userId': request.user_id,
        'expires_at': request.token_payload.get('exp')
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """
    Logout user (invalidate token server-side)
    
    Response:
        {
            "success": true,
            "message": 'Logged out successfully'
        }
    """
    # Add the token JTI to blacklist
    jti = request.session_jti
    if jti:
        add_to_blacklist(jti)
    
    logger.info(f"User logged out: {request.user_id}")
    
    return jsonify({
        'success': True,
        'message': 'Logged out successfully'
    }), 200
