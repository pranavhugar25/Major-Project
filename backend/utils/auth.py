"""
JWT Authentication utilities
Session-based authentication for zero-knowledge architecture

Provides JWT token generation and validation for securing API endpoints.
"""
import jwt
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional, Dict, Any, Set
from flask import request, jsonify, current_app

# Token configuration
TOKEN_EXPIRY_MINUTES = 15  # Short-lived tokens for security
REFRESH_TOKEN_EXPIRY_DAYS = 1  # Reduced from 7 days for improved security

# Token blacklist for logout (in production, use Redis)
token_blacklist: Set[str] = set()


def add_to_blacklist(jti: str) -> None:
    """
    Add a token to the blacklist
    
    Args:
        jti: JWT token ID (unique identifier)
    """
    token_blacklist.add(jti)


def is_blacklisted(jti: str) -> bool:
    """
    Check if a token is blacklisted
    
    Args:
        jti: JWT token ID
    
    Returns:
        True if token is blacklisted, False otherwise
    """
    return jti in token_blacklist


def remove_from_blacklist(jti: str) -> None:
    """
    Remove a token from the blacklist
    
    Args:
        jti: JWT token ID
    """
    token_blacklist.discard(jti)


def clear_blacklist() -> None:
    """Clear the entire blacklist (use with caution)"""
    token_blacklist.clear()


class AuthError(Exception):
    """Authentication error"""
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


def generate_session_token(user_id: str, additional_claims: Optional[Dict] = None) -> str:
    """
    Generate JWT session token with 15-minute expiration
    
    Args:
        user_id: User's unique identifier
        additional_claims: Optional additional claims to include
    
    Returns:
        Encoded JWT token string
    """
    now = datetime.now(timezone.utc)
    
    payload = {
        'user_id': user_id,
        'exp': now + timedelta(minutes=TOKEN_EXPIRY_MINUTES),
        'iat': now,
        'type': 'session',
        'jti': secrets.token_hex(16),  # Unique session ID
        'sub': user_id
    }
    
    # Add any additional claims
    if additional_claims:
        payload.update(additional_claims)
    
    return jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )


def generate_refresh_token(user_id: str) -> str:
    """
    Generate JWT refresh token with 7-day expiration
    
    Args:
        user_id: User's unique identifier
    
    Returns:
        Encoded JWT refresh token string
    """
    now = datetime.now(timezone.utc)
    
    payload = {
        'user_id': user_id,
        'exp': now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS),
        'iat': now,
        'type': 'refresh',
        'jti': secrets.token_hex(16)
    }
    
    return jwt.encode(
        payload,
        current_app.config['SECRET_KEY'],
        algorithm='HS256'
    )


def verify_session_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode session token
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded token payload
    
    Raises:
        AuthError: If token is invalid, expired, or blacklisted
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Verify token type
        if payload.get('type') != 'session':
            raise AuthError('Invalid token type')
        
        # Check if token is blacklisted
        jti = payload.get('jti')
        if jti and is_blacklisted(jti):
            raise AuthError('Token has been revoked')
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise AuthError('Session expired', 401)
    except jwt.InvalidTokenError:
        raise AuthError('Invalid or expired token', 401)


def verify_refresh_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode refresh token
    
    Args:
        token: JWT refresh token string
    
    Returns:
        Decoded token payload
    
    Raises:
        AuthError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(
            token,
            current_app.config['SECRET_KEY'],
            algorithms=['HS256']
        )
        
        # Verify token type
        if payload.get('type') != 'refresh':
            raise AuthError('Invalid token type')
        
        return payload
        
    except jwt.ExpiredSignatureError:
        raise AuthError('Refresh token expired', 401)
    except jwt.InvalidTokenError:
        raise AuthError('Invalid or expired refresh token', 401)


def require_auth(f):
    """
    Decorator to require valid JWT token on endpoint
    
    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            user_id = request.user_id
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({
                'success': False,
                'error': 'Missing authentication token'
            }), 401
        
        if not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Invalid token format. Use: Bearer <token>'
            }), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = verify_session_token(token)
            
            # Attach user info to request context
            request.user_id = payload['user_id']
            request.session_jti = payload['jti']
            request.token_payload = payload
            
        except AuthError as e:
            return jsonify({
                'success': False,
                'error': e.message
            }), e.status_code
        
        return f(*args, **kwargs)
    
    return decorated


def require_refresh_token(f):
    """
    Decorator to require valid refresh token
    
    Used for token refresh endpoints.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid refresh token'
            }), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = verify_refresh_token(token)
            request.user_id = payload['user_id']
            request.refresh_jti = payload['jti']
            
        except AuthError as e:
            return jsonify({
                'success': False,
                'error': e.message
            }), e.status_code
        
        return f(*args, **kwargs)
    
    return decorated


def get_token_from_request() -> Optional[str]:
    """
    Extract JWT token from Authorization header
    
    Returns:
        Token string or None if not present
    """
    auth_header = request.headers.get('Authorization')
    
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header.split(' ')[1]
    
    return None


class JWTAuth:
    """
    JWT Authentication helper class
    
    Provides methods for token management in a class-based approach.
    """
    
    @staticmethod
    def create_access_token(user_id: str) -> str:
        """Create short-lived access token"""
        return generate_session_token(user_id)
    
    @staticmethod
    def create_refresh_token(user_id: str) -> str:
        """Create long-lived refresh token"""
        return generate_refresh_token(user_id)
    
    @staticmethod
    def create_token_pair(user_id: str) -> Dict[str, str]:
        """Create both access and refresh tokens"""
        return {
            'access_token': JWTAuth.create_access_token(user_id),
            'refresh_token': JWTAuth.create_refresh_token(user_id),
            'token_type': 'Bearer',
            'expires_in': TOKEN_EXPIRY_MINUTES * 60  # seconds
        }
    
    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """Verify token and return payload"""
        return verify_session_token(token)
    
    @staticmethod
    def refresh_access_token(refresh_token: str) -> Dict[str, str]:
        """
        Use refresh token to get new access token
        
        Args:
            refresh_token: Valid refresh token
        
        Returns:
            New token pair dict
        """
        payload = verify_refresh_token(refresh_token)
        user_id = payload['user_id']
        
        return JWTAuth.create_token_pair(user_id)
