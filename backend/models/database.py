"""
Database models for the PQC Password Manager
"""
from flask_sqlalchemy import SQLAlchemy
import uuid
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    # PRIMARY KEY (only this)
    user_id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))

    username = db.Column(db.String(255), unique=True, nullable=False, index=True)
    master_password_hash = db.Column(db.String(1024), nullable=False)
    salt = db.Column(db.String(512), nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # relationship
    passwords = db.relationship('Password', back_populates='user', cascade='all, delete-orphan')

    def to_dict(self):
        return {
            'userId': str(self.user_id),
            'username': self.username,
            'salt': self.salt,
            'createdAt': self.created_at.isoformat() if self.created_at else None
        }


class Password(db.Model):
    """
    Password model - stores encrypted credentials per site
    Zero-knowledge: passwords are stored encrypted, server cannot decrypt
    """
    __tablename__ = 'passwords'
    
    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'), nullable=False, index=True)
    site_url = db.Column(db.String(512), nullable=False)
    site_username = db.Column(db.String(255), nullable=False)
    encrypted_password = db.Column(db.Text, nullable=False)  # Base64 encoded encrypted password
    iv = db.Column(db.String(512), nullable=False)  # Initialization vector for AES-GCM
    auth_tag = db.Column(db.String(512))  # Authentication tag for AES-GCM
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to user
    user = db.relationship('User', back_populates='passwords')
    
    # Composite unique constraint: one password per site per user
    __table_args__ = (
        db.UniqueConstraint('user_id', 'site_url', name='unique_user_site'),
    )
    
    def to_dict(self):
        """Convert password to dictionary"""
        return {
            'passwordId': str(self.password_id),
            'siteUrl': self.site_url,
            'siteUsername': self.site_username,
            'encryptedPassword': self.encrypted_password,
            'iv': self.iv,
            'authTag': self.auth_tag,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None
        }


class PQCSession(db.Model):
    """
    Post-Quantum Cryptography session data
    Stores ephemeral keys for PQC secure communication
    """
    __tablename__ = 'pqc_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey('users.user_id'), nullable=True, index=True)
    
    # ML-KEM (Kyber) public key for key encapsulation
    kyber_public_key = db.Column(db.Text, nullable=False)
    
    # ML-DSA (Dilithium) public key for signatures
    dilithium_public_key = db.Column(db.Text, nullable=False)
    
    # Session metadata
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    
    def to_dict(self):
        """Convert session to dictionary"""
        return {
            'sessionId': str(self.session_id),
            'kyberPublicKey': self.kyber_public_key,
            'dilithiumPublicKey': self.dilithium_public_key,
            'expiresAt': self.expires_at.isoformat() if self.expires_at else None,
            'isActive': self.is_active
        }
