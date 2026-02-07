"""
Authentication routes for user registration and login
Zero-knowledge architecture: master password never stored in plain text
"""
from flask import Blueprint, request, jsonify
from models.database import db, User
from utils.crypto import generate_salt, hash_password, verify_password
import uuid

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
        
        # Check if user already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return jsonify({
                'success': False,
                'error': 'Username already exists'
            }), 409
        
        # Generate unique salt for this user
        salt = generate_salt()
        
        # Hash the master password
        master_password_hash = hash_password(master_password, salt)
        
        # Create new user
        new_user = User(
            user_id=str(uuid.uuid4()),
            username=username,
            master_password_hash=master_password_hash,
            salt=salt
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'User registered successfully',
            'userId': str(new_user.user_id),
            'salt': salt,
            'username': username
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Registration failed: {str(e)}'
        }), 500


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Authenticate user and return salt for vault key derivation
    
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
            "username": "user@example.com"
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
        
        # Find user
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401
        
        # Verify password
        if not verify_password(master_password, user.salt, user.master_password_hash):
            return jsonify({
                'success': False,
                'error': 'Invalid username or password'
            }), 401
        
        # Successful login - return salt for client-side vault key derivation
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'userId': str(user.user_id),
            'salt': user.salt,
            'username': user.username
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Login failed: {str(e)}'
        }), 500


@auth_bp.route('/check-username', methods=['POST'])
def check_username():
    """
    Check if username is available
    
    Request body:
        {
            "username": "user@example.com"
        }
    
    Response:
        {
            "available": true/false
        }
    """
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({
                'success': False,
                'error': 'Username is required'
            }), 400
        
        user = User.query.filter_by(username=username).first()
        
        return jsonify({
            'available': user is None
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@auth_bp.route('/get-salt', methods=['POST'])
def get_salt():
    """
    Get salt for a username (used for vault unlock after page refresh)
    
    Request body:
        {
            "username": "user@example.com"
        }
    
    Response:
        {
            "success": true,
            "salt": "base64_salt"
        }
    """
    try:
        data = request.get_json()
        username = data.get('username')
        
        if not username:
            return jsonify({
                'success': False,
                'error': 'Username is required'
            }), 400
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        return jsonify({
            'success': True,
            'salt': user.salt
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
