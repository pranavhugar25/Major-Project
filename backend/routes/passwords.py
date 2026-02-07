"""
Password management routes
Handles storing and retrieving encrypted passwords
Zero-knowledge: all passwords stored encrypted, server cannot decrypt
"""
from flask import Blueprint, request, jsonify
from models.database import db, User, Password
import uuid

passwords_bp = Blueprint('passwords', __name__, url_prefix='/api/passwords')


@passwords_bp.route('/add', methods=['POST'])
def add_password():
    """
    Add a new encrypted password entry
    
    Request body:
        {
            "userId": "uuid",
            "siteUrl": "google.com",
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
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Extract data
        user_id_str = data.get('userId')
        site_url = data.get('siteUrl')
        site_username = data.get('siteUsername')
        encrypted_password = data.get('encryptedPassword')
        iv = data.get('iv')
        auth_tag = data.get('authTag')
        
        # Validation
        if not all([user_id_str, site_url, site_username, encrypted_password, iv]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields'
            }), 400
        
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
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Password updated successfully',
                'passwordId': str(existing_password.password_id)
            }), 200
        
        # Create new password entry
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
        
        return jsonify({
            'success': True,
            'message': 'Password saved successfully',
            'passwordId': str(new_password.password_id)
        }), 201
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Failed to save password: {str(e)}'
        }), 500


@passwords_bp.route('/get-all', methods=['POST'])
def get_all_passwords():
    """
    Get all encrypted passwords for a user
    
    Request body:
        {
            "userId": "uuid"
        }
    
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
        data = request.get_json()
        user_id_str = data.get('userId')
        
        if not user_id_str:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            }), 400
        
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
        
        return jsonify({
            'success': True,
            'passwords': passwords_list
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve passwords: {str(e)}'
        }), 500


@passwords_bp.route('/delete', methods=['POST'])
def delete_password():
    """
    Delete a password entry
    
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
        password_id_str = data.get('passwordId')
        
        if not password_id_str:
            return jsonify({
                'success': False,
                'error': 'Password ID is required'
            }), 400
        
        # Find password
        password = Password.query.filter_by(password_id=password_id_str).first()
        if not password:
            return jsonify({
                'success': False,
                'error': 'Password not found'
            }), 404
        
        db.session.delete(password)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Password deleted successfully'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'error': f'Failed to delete password: {str(e)}'
        }), 500


@passwords_bp.route('/get-crypto-view', methods=['POST'])
def get_crypto_view():
    """
    Get encrypted password data for transparency/demonstration
    Shows that server only stores encrypted data
    
    Request body:
        {
            "userId": "uuid"
        }
    
    Response:
        {
            "success": true,
            "cryptoData": {
                "username": "user@example.com",
                "passwords": [
                    {
                        "siteUrl": "google.com",
                        "encryptedData": "...",
                        "iv": "...",
                        "note": "Server cannot decrypt this"
                    }
                ]
            }
        }
    """
    try:
        data = request.get_json()
        user_id_str = data.get('userId')
        
        if not user_id_str:
            return jsonify({
                'success': False,
                'error': 'User ID is required'
            }), 400
        
        # Find user
        user = User.query.filter_by(user_id=user_id_str).first()
        if not user:
            return jsonify({
                'success': False,
                'error': 'User not found'
            }), 404
        
        # Get all passwords
        passwords = Password.query.filter_by(user_id=user.user_id).all()
        
        crypto_view = {
            'username': user.username,
            'userId': str(user.user_id),
            'salt': user.salt,
            'masterPasswordHash': user.master_password_hash,
            'note': 'This is the server-side view. Notice that passwords are encrypted.',
            'passwords': []
        }
        
        for pwd in passwords:
            crypto_view['passwords'].append({
                'siteUrl': pwd.site_url,
                'siteUsername': pwd.site_username,
                'encryptedPassword': pwd.encrypted_password[:50] + '...',  # Truncate for display
                'iv': pwd.iv,
                'authTag': pwd.auth_tag if pwd.auth_tag else 'N/A',
                'note': 'Server stores only encrypted ciphertext - cannot decrypt without vault key'
            })
        
        return jsonify({
            'success': True,
            'cryptoData': crypto_view
        }), 200
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Failed to retrieve crypto view: {str(e)}'
        }), 500
