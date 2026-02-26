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
    pqc_envelope = db.relationship(
        'PasswordPQCEnvelope',
        back_populates='password',
        cascade='all, delete-orphan',
        uselist=False,
    )
    
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


class PasswordPQCEnvelope(db.Model):
    """
    PQC envelope data for encrypted password payloads.

    The client ciphertext is wrapped with ML-KEM-derived symmetric encryption
    and signed with ML-DSA to make PQC part of the active storage flow.
    """
    __tablename__ = 'password_pqc_envelopes'

    id = db.Column(db.Integer, primary_key=True)
    password_id = db.Column(
        db.String(36),
        db.ForeignKey('passwords.password_id', ondelete='CASCADE'),
        nullable=False,
        unique=True,
        index=True,
    )
    kem_ciphertext = db.Column(db.Text, nullable=False)
    encrypted_kem_private_key = db.Column(db.Text, nullable=False)
    kem_private_key_iv = db.Column(db.String(512), nullable=False)
    payload_ciphertext = db.Column(db.Text, nullable=False)
    payload_iv = db.Column(db.String(512), nullable=False)
    payload_signature = db.Column(db.Text, nullable=False)
    signature_public_key = db.Column(db.Text, nullable=False)
    pqc_algorithm = db.Column(db.String(128), nullable=False, default='ML-KEM-1024+ML-DSA-87')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    password = db.relationship('Password', back_populates='pqc_envelope')

    def to_dict(self):
        return {
            'passwordId': str(self.password_id),
            'pqcAlgorithm': self.pqc_algorithm,
            'createdAt': self.created_at.isoformat() if self.created_at else None,
            'updatedAt': self.updated_at.isoformat() if self.updated_at else None,
        }
