"""
Password management routes
Handles storing and retrieving encrypted passwords
Zero-knowledge: all passwords stored encrypted, server cannot decrypt

All endpoints require JWT authentication via Bearer token.
"""
from flask import Blueprint, request, jsonify
from models.database import db, User, Password
from utils.auth import require_auth
import uuid
import re
import logging

logger = logging.getLogger(__name__)

passwords_bp = Blueprint('passwords', __name__, url_prefix='/api/passwords')


def validate_site_url(site_url: str) -> str:
    """
    Validate and sanitize site URL
    
    Args:
        site_url: URL to validate
    
    Returns:
        Normalized URL
    
    Raises:
        ValueError: If URL is invalid
    """
    # Maximum length
    if len(site_url) > 512:
        raise ValueError('URL exceeds maximum length')
    
    # Block dangerous schemes
    if site_url.lower().startswith(('javascript:', 'data:', 'file:')):
        raise ValueError('URL scheme not allowed')
    
    # Allow any format, just normalize
    site_url = site_url.strip()
    
    # Remove trailing slash for consistency
    site_url = site_url.rstrip('/')
    
    return site_url.lower()


@passwords_bp.route('/add', methods=['POST'])
@require_auth
def add_password():
    """
    Add a new encrypted password entry
    
    Requires JWT authentication via Bearer token.
    
    Request body:
        {
            "siteUrl": "https://google.com",
            "siteUsername": "user@gmail.com",
            "encryptedPassword": "base64_encrypted_data",
            "iv": "base64_iv",
            "authTag": "base64_auth_tag"
        }
    
    Response:
        {
            "success": true,
            "message": "Password saved successfully",
            "passwordId": "uuid"
        }
    """
    try:
        data = request.get_json()
        user_id_str = request.user_id
        
        logger.info(f"[PASSWORDS] add_password called by user_id={user_id_str}")
        
        if not data:
            logger.warning("[PASSWORDS] No data provided in request")
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Extract data
        site_url = data.get('siteUrl')
        site_username = data.get('siteUsername')
        encrypted_password = data.get('encryptedPassword')
        iv = data.get('iv')
        auth_tag = data.get('authTag')
        
        # Log encryption details for debugging
        logger.info(f"[PASSWORDS] Received encryption data:")
        logger.info(f"  - siteUrl: {site_url}")
        logger.info(f"  - encryptedPassword present: {'Yes' if encrypted_password else 'No'}")
        logger.info(f"  - iv present: {'Yes' if iv else 'No'}")
        logger.info(f"  - auth_tag present: {'Yes' if auth_tag else 'No'}")
        
        # Check if PQC fields are present (these would be used if PQC key encapsulation was implemented)
        pqc_ciphertext = data.get('pqcCiphertext')
        pqc_public_key = data.get('pqcPublicKey')
        
        if pqc_ciphertext:
            logger.info(f"[PASSWORDS] ═ PQC data detected! PQC ciphertext length={len(pqc_ciphertext)}")
        else:
            logger.info(f"[PASSWORDS] ═ No PQC data - using classical AES-256-GCM only")
        
        # Validation - check for None/empty strings, not falsy values
        # auth_tag can be empty string (Web Crypto API handles auth tag internally)
        if site_url is None or site_username is None or encrypted_password is None or iv is None:
            logger.warning("[PASSWORDS] Missing required fields")
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
        # Validate site URL
        try:
            site_url = validate_site_url(site_url)
        except ValueError as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 400
        
        # Validate maximum field lengths
        if len(site_url) > 512:
            return jsonify({
                'success': False,
                'error': 'Site URL too long'
            }), 400
        
        if len(site_username) > 255:
            return jsonify({
                'success': False,
                'error': 'Site username too long'
            }), 400
        
        # Get user from JWT token (set by @require_auth decorator)
        user_id_str = request.user_id
        
        # Find user
        user = User.query.filter_by(user_id=user_id_str).first()
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Check if password already exists for this site
        existing_password = Password.query.filter_by(
            user_id=user.user_id,
            site_url=site_url
        ).first()
        
        if existing_password:
            # Update existing password
            existing_password.site_username = site_username
            existing_password.encrypted_password = encrypted_password
            existing_password.iv = iv
            existing_password.auth_tag = auth_tag
            
            logger.info(f"[PASSWORDS] Updating existing password for user {user_id_str}: {site_url}")
            
            db.session.commit()
            
            logger.info(f"[PASSWORDS] ✓ Password updated successfully for {site_url}")
            
            return jsonify({
                'success': True,
                'message': 'Password updated successfully',
                'passwordId': str(existing_password.password_id)
            }), 200
        
        # Create new password entry
        logger.info(f"[PASSWORDS] Creating new password entry for user {user_id_str}: {site_url}")
        new_password = Password(
            password_id=str(uuid.uuid4()),
            user_id=user.user_id,
            site_url=site_url,
            site_username=site_username,
            encrypted_password=encrypted_password,
            iv=iv,
            auth_tag=auth_tag
        )
        
        db.session.add(new_password)
        db.session.commit()
        
        logger.info(f"[PASSWORDS] ✓ New password saved successfully: id={new_password.password_id}, site={site_url}")
        
        return jsonify({
            'success': True,
            'message': 'Password saved successfully',
            'passwordId': str(new_password.password_id)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to save password: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to save password. Please try again.'
        }), 500


@passwords_bp.route('/get-all', methods=['POST'])
@require_auth
def get_all_passwords():
    """
    Get all encrypted passwords for authenticated user
    
    Requires JWT authentication via Bearer token.
    
    Request body:
        {}  # No data needed, user_id from token
    
    Response:
        {
            "success": true,
            "passwords": [
                {
                    "passwordId": "uuid",
                    "siteUrl": "google.com",
                    "siteUsername": "user@gmail.com",
                    "encryptedPassword": "base64_encrypted_data",
                    "iv": "base64_iv",
                    "authTag": "base64_auth_tag",
                    "createdAt": "2024-01-01T00:00:00",
                    "updatedAt": "2024-01-01T00:00:00"
                }
            ]
        }
    """
    try:
        # Get user from JWT token
        user_id_str = request.user_id
        
        # Find user
        user = User.query.filter_by(user_id=user_id_str).first()
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Get all passwords for user
        passwords = Password.query.filter_by(user_id=user.user_id).all()
        
        passwords_list = [pwd.to_dict() for pwd in passwords]
        
        logger.info(f"Retrieved {len(passwords_list)} passwords for user {user_id_str}")
        
        return jsonify({
            'success': True,
            'passwords': passwords_list
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to retrieve passwords: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve passwords. Please try again.'
        }), 500


@passwords_bp.route('/delete', methods=['POST'])
@require_auth
def delete_password():
    """
    Delete a password entry
    
    Requires JWT authentication via Bearer token.
    
    Request body:
        {
            "passwordId": "uuid"
        }
    
    Response:
        {
            "success": true,
            "message": "Password deleted successfully"
        }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        password_id = data.get('passwordId')
        
        if not password_id:
            return jsonify({
                'success': False,
                'error': 'Password ID is required'
            }), 400
        
        # Get user from JWT token
        user_id_str = request.user_id
        user = User.query.filter_by(user_id=user_id_str).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Find password belonging to user
        password = Password.query.filter_by(
            password_id=password_id,
            user_id=user.user_id
        ).first()
        
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password not found'
            }), 404
        
        # Delete password
        db.session.delete(password)
        db.session.commit()
        
        logger.info(f"Password deleted for user {user_id_str}: {password.site_url}")
        
        return jsonify({
            'success': True,
            'message': 'Password deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete password: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete password. Please try again.'
        }), 500


@passwords_bp.route('/get-crypto-view', methods=['POST'])
@require_auth
def get_crypto_view():
    """
    Get a view of the encrypted data (for transparency/debugging)
    
    Requires JWT authentication via Bearer token.
    
    Response:
        {
            "success": true,
            "encrypted_data": [...],
            "total_entries": 5
        }
    """
    try:
        # Get user from JWT token
        user_id_str = request.user_id
        user = User.query.filter_by(user_id=user_id_str).first()
        
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        passwords = Password.query.filter_by(user_id=user.user_id).all()
        
        # Return encrypted data view with user info
        encrypted_data = [{
            'passwordId': str(pwd.password_id),
            'siteUrl': pwd.site_url,
            'siteUsername': pwd.site_username,
            'encryptedPassword': pwd.encrypted_password,
            'iv': pwd.iv,
            'authTag': pwd.auth_tag or '',
            'note': 'AES-256-GCM encrypted data',
            'createdAt': pwd.created_at.isoformat(),
            'updatedAt': pwd.updated_at.isoformat()
        } for pwd in passwords]
        
        return jsonify({
            'success': True,
            'username': user.username,
            'userId': str(user.user_id),
            'salt': user.salt,
            'passwords': encrypted_data,
            'total_entries': len(encrypted_data)
        }), 200
        
    except Exception as e:
        logger.error(f"Failed to get crypto view: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve crypto view. Please try again.'
        }), 500
