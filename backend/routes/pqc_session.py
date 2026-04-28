"""
PQC Session Management Endpoints
Post-Quantum Cryptography session handling with ML-KEM-1024

This module provides session management endpoints for PQC-authenticated
sessions, including initialization, heartbeat, logout, and status checking.

Endpoints:
- POST /api/auth/pqc/init - Initialize PQC session with ML-KEM-1024 keypair
- POST /api/auth/pqc/heartbeat - Update session activity timestamp
- POST /api/auth/pqc/logout - Destroy PQC session
- GET /api/auth/pqc/status - Get session status
"""
import os
import secrets
import logging
import base64
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any
from flask import Blueprint, request, jsonify, current_app

# Import PQC utilities
from utils.pqc import (
    PQCKeyManager, PQCError,
    sign_session_data, get_server_mldsa_public_key
)
from utils.auth import require_auth

# Configure logging
logger = logging.getLogger(__name__)

# Create blueprint
pqc_session_bp = Blueprint('pqc_session', __name__, url_prefix='/api/auth/pqc')

# ====================================================================
# Session Configuration
# ====================================================================

def get_idle_timeout_minutes() -> int:
    """Get idle timeout from environment variable or use default (5 minutes)"""
    try:
        return int(os.environ.get('IDLE_TIMEOUT_MINUTES', 5))
    except ValueError:
        logger.warning("Invalid IDLE_TIMEOUT_MINUTES, using default 5")
        return 5


def get_session_duration_hours() -> int:
    """Get session duration from environment variable or use default (24 hours)"""
    try:
        return int(os.environ.get('PQC_SESSION_DURATION_HOURS', 24))
    except ValueError:
        logger.warning("Invalid PQC_SESSION_DURATION_HOURS, using default 24")
        return 24


# ====================================================================
# In-Memory Session Storage
# ====================================================================

# Session storage: {session_id: SessionData}
class PQCSessionData:
    """PQC Session data container"""
    def __init__(
        self,
        session_id: str,
        user_id: Optional[str],
        public_key: str,
        private_key: str,
        created_at: datetime,
        expires_at: datetime,
        last_activity: datetime,
        oprf_seed: Optional[str] = None
    ):
        self.session_id = session_id
        self.user_id = user_id
        self.public_key = public_key
        self.private_key = private_key
        self.created_at = created_at
        self.expires_at = expires_at
        self.last_activity = last_activity
        self.oprf_seed = oprf_seed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session data to dictionary"""
        return {
            'session_id': self.session_id,
            'user_id': self.user_id,
            'public_key': self.public_key,
            'created_at': self.created_at.isoformat(),
            'expires_at': self.expires_at.isoformat(),
            'last_activity': self.last_activity.isoformat()
        }
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now(timezone.utc) > self.expires_at
    
    def is_idle_timeout(self) -> bool:
        """Check if session has exceeded idle timeout"""
        idle_timeout = get_idle_timeout_minutes()
        last_activity = self.last_activity.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (now - last_activity).total_seconds() > (idle_timeout * 60)
    
    def update_activity(self) -> None:
        """Update last activity timestamp"""
        self.last_activity = datetime.now(timezone.utc)


# In-memory session store
pqc_sessions: Dict[str, PQCSessionData] = {}


def create_session(
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    oprf_seed: Optional[str] = None
) -> PQCSessionData:
    """
    Create a new PQC session with ML-KEM-1024 keypair
    
    Args:
        user_id: Optional user ID if authenticated
        username: Optional username for OPRF seed pre-loading
        oprf_seed: Optional pre-loaded OPRF seed
    
    Returns:
        PQCSessionData object
    """
    # Generate session ID
    session_id = secrets.token_hex(32)
    
    # Generate ML-KEM-1024 keypair
    public_key, private_key = PQCKeyManager.generate_kyber_keypair()
    
    # Calculate expiration
    now = datetime.now(timezone.utc)
    duration_hours = get_session_duration_hours()
    expires_at = now + timedelta(hours=duration_hours)
    
    # If username provided but no OPRF seed, generate a deterministic seed
    # This is a placeholder - in production, the OPRF seed would come from
    # a more secure source or be derived from user credentials
    if username and not oprf_seed:
        # Generate a deterministic seed based on username
        # In production, this would use proper key derivation
        oprf_seed = f"oprf_seed_{username}_{secrets.token_hex(16)}"
    
    session_data = PQCSessionData(
        session_id=session_id,
        user_id=user_id,
        public_key=public_key,
        private_key=private_key,
        created_at=now,
        expires_at=expires_at,
        last_activity=now,
        oprf_seed=oprf_seed
    )
    
    # Store session
    pqc_sessions[session_id] = session_data
    
    logger.info(f"PQC session created: {session_id[:16]}... (user: {user_id or 'anonymous'})")
    
    return session_data


def get_session(session_id: str) -> Optional[PQCSessionData]:
    """
    Get session by ID
    
    Args:
        session_id: Session identifier
    
    Returns:
        PQCSessionData if found and valid, None otherwise
    """
    session = pqc_sessions.get(session_id)
    
    if session is None:
        return None
    
    # Check expiration
    if session.is_expired():
        logger.warning(f"PQC session expired: {session_id[:16]}...")
        delete_session(session_id)
        return None
    
    # Check idle timeout
    if session.is_idle_timeout():
        logger.warning(f"PQC session idle timeout: {session_id[:16]}...")
        delete_session(session_id)
        return None
    
    return session


def delete_session(session_id: str) -> bool:
    """
    Delete a PQC session
    
    Args:
        session_id: Session identifier
    
    Returns:
        True if session was deleted, False if not found
    """
    if session_id in pqc_sessions:
        # Clear sensitive data before deletion
        session = pqc_sessions[session_id]
        session.private_key = "DELETED"
        session.oprf_seed = "DELETED"
        
        del pqc_sessions[session_id]
        logger.info(f"PQC session deleted: {session_id[:16]}...")
        return True
    
    return False


def cleanup_expired_sessions() -> int:
    """
    Remove all expired sessions
    
    Returns:
        Number of sessions removed
    """
    now = datetime.now(timezone.utc)
    expired = [
        sid for sid, session in pqc_sessions.items()
        if session.is_expired() or session.is_idle_timeout()
    ]
    
    for sid in expired:
        delete_session(sid)
    
    if expired:
        logger.info(f"Cleaned up {len(expired)} expired PQC sessions")
    
    return len(expired)


# ====================================================================
# API Endpoints
# ====================================================================

@pqc_session_bp.route('/init', methods=['POST'])
def init_session():
    """
    POST /api/auth/pqc/init
    
    Initialize a new PQC session with ML-KEM-1024 keypair
    
    Request Body (JSON):
        username (optional): Username to pre-load OPRF seed
        user_id (optional): User ID if already authenticated
    
    Returns:
        JSON with session_id, server_public_key, expires_at,
        server_signing_key (ML-DSA-87 public key),
        session_signature (ML-DSA-87 signature of session_id)
    """
    try:
        # Parse request body
        data = request.get_json() or {}
        username = data.get('username')
        user_id = data.get('user_id')
        
        # Create new session
        session = create_session(
            user_id=user_id,
            username=username
        )
        
        # Sign the session ID with server's ML-DSA-87 private key
        logger.info(f"[PQC_SESSION] Signing session {session.session_id[:16]}... with ML-DSA-87")
        session_signature = sign_session_data(session.session_id)
        server_signing_key = get_server_mldsa_public_key()
        
        logger.info(f"[PQC_SESSION] ✓ Session created: id={session.session_id[:32]}...")
        logger.info(f"[PQC_SESSION] ✓ Session signed with ML-DSA-87")
        logger.info(f"[PQC_SESSION] Debug info:")
        logger.info(f"  - server_signing_key length: {len(server_signing_key) if server_signing_key else 'None'} chars (base64)")
        logger.info(f"  - session_signature length: {len(session_signature)} chars (base64)")
        logger.info(f"  - session_signature (first 50): {session_signature[:50] if session_signature else 'None'}")
        
        return jsonify({
            'success': True,
            'session_id': session.session_id,
            'server_public_key': session.public_key,
            'algorithm': 'ML-KEM-1024',
            'server_signing_key': server_signing_key,
            'session_signature': session_signature,
            'expires_at': session.expires_at.isoformat(),
            'idle_timeout_minutes': get_idle_timeout_minutes()
        }), 200
        
    except PQCError as e:
        logger.error(f"PQC error during session init: {e}")
        return jsonify({
            'success': False,
            'error': 'Failed to initialize PQC session'
        }), 500
    except Exception as e:
        logger.error(f"Error initializing PQC session: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@pqc_session_bp.route('/confirm', methods=['POST'])
def confirm_session():
    """Receive client ML-KEM-1024 public key to finalize PQC session"""
    logger.info("[PQC_SESSION] /confirm endpoint called")
    data = request.get_json() or {}
    session_id = data.get('session_id')
    client_pub_key = data.get('client_public_key')  # Expected as JSON array of ints

    if not session_id or not client_pub_key:
        logger.error("[PQC_SESSION] Missing session_id or client_public_key")
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    session = pqc_sessions.get(session_id)
    if not session:
        logger.warning(f"[PQC_SESSION] Session not found: {session_id}")
        return jsonify({'success': False, 'error': 'Session not found'}), 404

    # Convert client public key array to base64 string for storage
    if isinstance(client_pub_key, list):
        # Convert list of ints to bytes then to base64
        client_pub_bytes = bytes(client_pub_key)
        client_pub_key_b64 = base64.b64encode(client_pub_bytes).decode('utf-8')
    else:
        # Already base64 string
        client_pub_key_b64 = client_pub_key

    session.client_public_key = client_pub_key_b64
    logger.info(f"[PQC_SESSION] Client public key stored for session {session_id[:8]}...")
    return jsonify({'success': True, 'message': 'Client public key accepted'}), 200


@pqc_session_bp.route('/server-signing-key', methods=['GET'])
def get_server_signing_key():
    """Get server's ML-DSA-87 public key for signature verification"""
    logger.info("[PQC_SESSION] /server-signing-key endpoint called")
    try:
        public_key = get_server_mldsa_public_key()
        if not public_key:
            return jsonify({
                'success': False,
                'error': 'Server signing key not initialized'
            }), 500
        
        logger.info("[PQC_SESSION] ✓ Returning server ML-DSA-87 public key")
        return jsonify({
            'success': True,
            'algorithm': 'ML-DSA-87',
            'public_key': public_key
        }), 200
    except Exception as e:
        logger.error(f"Error getting server signing key: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@pqc_session_bp.route('/heartbeat', methods=['POST'])
@require_auth
def heartbeat():
    """
    POST /api/auth/pqc/heartbeat
    
    Update last activity timestamp and reset idle timer
    
    Request Body (JSON):
        session_id: PQC session ID
    
    Returns:
        JSON with success status and updated last_activity
    """
    try:
        # Get user ID from JWT
        user_id = request.user_id
        
        # Parse request body
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({
                'success': False,
                'error': 'session_id is required'
            }), 400
        
        # Get and validate session
        session = get_session(session_id)
        
        if session is None:
            return jsonify({
                'success': False,
                'error': 'Invalid or expired session'
            }), 404
        
        # Verify session belongs to user
        if session.user_id and session.user_id != user_id:
            logger.warning(f"Session mismatch: {session.user_id} != {user_id}")
            return jsonify({
                'success': False,
                'error': 'Session does not belong to user'
            }), 403
        
        # Update activity
        session.update_activity()
        
        return jsonify({
            'success': True,
            'session_id': session.session_id,
            'last_activity': session.last_activity.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'idle_timeout_minutes': get_idle_timeout_minutes()
        }), 200
        
    except Exception as e:
        logger.error(f"Error in PQC heartbeat: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@pqc_session_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """
    POST /api/auth/pqc/logout
    
    Destroy PQC session and clear session keys
    
    Request Body (JSON):
        session_id: PQC session ID
    
    Returns:
        JSON with success status
    """
    try:
        # Get user ID from JWT
        user_id = request.user_id
        
        # Parse request body
        data = request.get_json() or {}
        session_id = data.get('session_id')
        
        if not session_id:
            return jsonify({
                'success': False,
                'error': 'session_id is required'
            }), 400
        
        # Get session to verify ownership
        session = pqc_sessions.get(session_id)
        
        if session is None:
            return jsonify({
                'success': False,
                'error': 'Session not found'
            }), 404
        
        # Verify session belongs to user
        if session.user_id and session.user_id != user_id:
            logger.warning(f"Session logout mismatch: {session.user_id} != {user_id}")
            return jsonify({
                'success': False,
                'error': 'Session does not belong to user'
            }), 403
        
        # Delete session
        delete_session(session_id)
        
        return jsonify({
            'success': True,
            'message': 'PQC session destroyed successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in PQC logout: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


@pqc_session_bp.route('/status', methods=['GET'])
@require_auth
def get_status():
    """
    GET /api/auth/pqc/status
    
    Get PQC session status
    
    Query Parameters:
        session_id: PQC session ID
    
    Returns:
        JSON with session status (active, expires_at, last_activity)
    """
    try:
        # Get user ID from JWT
        user_id = request.user_id
        
        # Get session_id from query params
        session_id = request.args.get('session_id')
        
        if not session_id:
            return jsonify({
                'success': False,
                'error': 'session_id query parameter is required'
            }), 400
        
        # Get session
        session = get_session(session_id)
        
        if session is None:
            return jsonify({
                'success': False,
                'error': 'Invalid or expired session'
            }), 404
        
        # Verify session belongs to user
        if session.user_id and session.user_id != user_id:
            logger.warning(f"Session status mismatch: {session.user_id} != {user_id}")
            return jsonify({
                'success': False,
                'error': 'Session does not belong to user'
            }), 403
        
        # Calculate time remaining
        now = datetime.now(timezone.utc)
        expires_at = session.expires_at.replace(tzinfo=timezone.utc)
        time_remaining = (expires_at - now).total_seconds()
        
        return jsonify({
            'success': True,
            'session_id': session.session_id,
            'active': True,
            'user_id': session.user_id,
            'created_at': session.created_at.isoformat(),
            'expires_at': session.expires_at.isoformat(),
            'last_activity': session.last_activity.isoformat(),
            'time_remaining_seconds': max(0, time_remaining),
            'idle_timeout_minutes': get_idle_timeout_minutes(),
            'algorithm': 'ML-KEM-1024'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in PQC status: {e}")
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500


# ====================================================================
# Health Check for Session Manager
# ====================================================================

@pqc_session_bp.route('/sessions', methods=['GET'])
def list_sessions():
    """
    GET /api/auth/pqc/sessions
    
    Get count of active sessions (for debugging/monitoring)
    
    Returns:
        JSON with session count
    """
    # Clean up expired sessions first
    cleanup_expired_sessions()
    
    return jsonify({
        'success': True,
        'active_sessions': len(pqc_sessions),
        'idle_timeout_minutes': get_idle_timeout_minutes(),
        'session_duration_hours': get_session_duration_hours()
    }), 200
