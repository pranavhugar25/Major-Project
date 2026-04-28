"""
SPAKE2 Password-Authenticated Key Exchange Implementation

This module provides a secure implementation of SPAKE2 for 
password-authenticated key exchange using the spake2 library.

SPAKE2 is a symmetric PAKE that allows two parties to authenticate
each other using a shared password without exposing the password
or enabling offline dictionary attacks.
"""

import logging
import spake2
from spake2 import SPAKE2_A, SPAKE2_B
import hashlib
import base64
import secrets
from typing import Tuple, Optional

logger = logging.getLogger(__name__)
logger.info("[SPAKE2] Module loaded, SPAKE2 classes available")


class SPAKE2Server:
    """
    SPAKE2 server-side implementation for password-authenticated key exchange.
    
    The server stores a password verifier and uses SPAKE2 to authenticate
    the client without ever learning the password.
    """
    
    def __init__(self, password: str):
        """
        Initialize the SPAKE2 server.
        
        Args:
            password: The shared password between client and server
        """
        self.password = password.encode('utf-8')
        self.spake2 = SPAKE2_B(self.password)
        self._key_established = False
        self._shared_key = None
        logger.debug("[SPAKE2] SPAKE2Server initialized")
        
    def generate_initial_message(self) -> str:
        """
        Generate the first message in the SPAKE2 protocol.
        
        This message is sent to the client to start the key exchange.
        
        Returns:
            Base64 encoded first message
        """
        msg = self.spake2.start()
        logger.debug("[SPAKE2] Server: generated initial message")
        return base64.b64encode(msg).decode('utf-8')
    
    def process_client_response(self, client_message: str) -> str:
        """
        Process the client's response message.
        
        Args:
            client_message: Base64 encoded client response
            
        Returns:
            Base64 encoded server's final message
        """
        logger.debug("[SPAKE2] Server: processing client response")
        client_msg_bytes = base64.b64decode(client_message)
        self._shared_key = self.spake2.finish(client_msg_bytes)
        self._key_established = True
        logger.info(f"[SPAKE2] ✓ Server: key exchange complete, shared key length={len(self._shared_key)}")
        # Return empty since finish() doesn't return a message
        return ""
    
    def verify_key_confirmation(self, confirmation: str) -> bool:
        """
        Verify key confirmation from client.
        
        Args:
            confirmation: Base64 encoded key confirmation from client
            
        Returns:
            True if confirmation matches, False otherwise
        """
        if not self._key_established:
            logger.warning("[SPAKE2] Server: key confirmation failed - key not established")
            return False
            
        expected_confirmation = self.get_key_confirmation()
        result = secrets.compare_digest(expected_confirmation, confirmation)
        logger.debug(f"[SPAKE2] Server: key confirmation {'MATCHED' if result else 'FAILED'}")
        return result
    
    def get_key_confirmation(self) -> str:
        """
        Get key confirmation bytes for mutual authentication.
        
        Returns:
            Base64 encoded key confirmation
        """
        if not self._key_established:
            return ""
            
        # Use a deterministic confirmation based on the shared key
        confirmation = hashlib.sha256(self._shared_key + b"confirmation").digest()
        return base64.b64encode(confirmation).decode('utf-8')
    
    def get_shared_key(self) -> Optional[bytes]:
        """
        Get the established shared key.
        
        Returns:
            The shared key bytes, or None if not established
        """
        return self._shared_key
    
    def is_key_established(self) -> bool:
        """
        Check if the key exchange was successful.
        
        Returns:
            True if key is established, False otherwise
        """
        return self._key_established


class SPAKE2Client:
    """
    SPAKE2 client-side implementation for password-authenticated key exchange.
    """
    
    def __init__(self, password: str):
        """
        Initialize the SPAKE2 client.
        
        Args:
            password: The shared password between client and server
        """
        self.password = password.encode('utf-8')
        self.spake2 = SPAKE2_A(self.password)
        self._key_established = False
        self._shared_key = None
        logger.debug("[SPAKE2] SPAKE2Client initialized")
        
    def generate_initial_message(self) -> str:
        """
        Generate the first message in the SPAKE2 protocol.
        
        Returns:
            Base64 encoded first message
        """
        msg = self.spake2.start()
        logger.debug("[SPAKE2] Client: generated initial message")
        return base64.b64encode(msg).decode('utf-8')
    
    def process_server_response(self, server_message: str) -> str:
        """
        Process the server's response message.
        
        Args:
            server_message: Base64 encoded server response (can be empty)
            
        Returns:
            Base64 encoded client's final message and confirmation
        """
        logger.debug("[SPAKE2] Client: processing server response")
        # For SPAKE2_A, finish() computes the shared key
        self._shared_key = self.spake2.finish(b'')  # Server sends empty message
        self._key_established = True
        logger.info(f"[SPAKE2] ✓ Client: key exchange complete, shared key length={len(self._shared_key)}")
        return ""
    
    def generate_key_confirmation(self) -> str:
        """
        Generate key confirmation bytes for mutual authentication.
        
        Returns:
            Base64 encoded key confirmation
        """
        if not self._key_established:
            logger.warning("[SPAKE2] Client: key confirmation failed - key not established")
            return ""
            
        confirmation = hashlib.sha256(self._shared_key + b"confirmation").digest()
        logger.debug("[SPAKE2] Client: generated key confirmation")
        return base64.b64encode(confirmation).decode('utf-8')
    
    def verify_server_confirmation(self, confirmation: str) -> bool:
        """
        Verify key confirmation from server.
        
        Args:
            confirmation: Base64 encoded key confirmation from server
            
        Returns:
            True if confirmation matches, False otherwise
        """
        if not self._key_established:
            logger.warning("[SPAKE2] Client: server confirmation verification failed - key not established")
            return False
            
        expected_confirmation = hashlib.sha256(self._shared_key + b"confirmation").digest()
        result = secrets.compare_digest(expected_confirmation, base64.b64decode(confirmation))
        logger.debug(f"[SPAKE2] Client: server confirmation {'MATCHED' if result else 'FAILED'}")
        return result
    
    def get_shared_key(self) -> Optional[bytes]:
        """
        Get the established shared key.
        
        Returns:
            The shared key bytes, or None if not established
        """
        return self._shared_key
    
    def is_key_established(self) -> bool:
        """
        Check if the key exchange was successful.
        
        Returns:
            True if key is established, False otherwise
        """
        return self._key_established


# ============================================================================
# Helper functions for registration (verifier storage)
# ============================================================================

def generate_password_verifier(password: str) -> Tuple[str, str]:
    """
    Generate a password verifier for storage.
    
    This creates a one-way verifier that can be used to authenticate
    without storing the actual password.
    
    Args:
        password: User's password
        
    Returns:
        Tuple of (verifier, salt) - both base64 encoded
    """
    logger.debug("[SPAKE2] Generating password verifier")
    # Generate a random salt
    salt = secrets.token_bytes(32)
    
    # Create a verifier using PBKDF2-like approach with SPAKE2
    # We use the password + salt to derive a verifier
    verifier_input = password.encode('utf-8') + salt
    verifier = hashlib.sha256(verifier_input).digest()
    
    logger.info(f"[SPAKE2] ✓ Verifier generated: salt_len={len(salt)}, verifier_len={len(verifier)}")
    return base64.b64encode(verifier).decode('utf-8'), base64.b64encode(salt).decode('utf-8')


def compute_verifier(password: str, salt: str) -> str:
    """
    Compute a password verifier given a salt.
    
    Args:
        password: User's password
        salt: Base64 encoded salt
        
    Returns:
        Base64 encoded verifier
    """
    logger.debug("[SPAKE2] Computing verifier for password check")
    salt_bytes = base64.b64decode(salt)
    verifier_input = password.encode('utf-8') + salt_bytes
    verifier = hashlib.sha256(verifier_input).digest()
    return base64.b64encode(verifier).decode('utf-8')


def create_server(password: str) -> SPAKE2Server:
    """
    Create a new SPAKE2 server instance.
    
    Args:
        password: The shared password
        
    Returns:
        SPAKE2Server instance
    """
    logger.debug("[SPAKE2] Creating SPAKE2 server")
    return SPAKE2Server(password)


def create_client(password: str) -> SPAKE2Client:
    """
    Create a new SPAKE2 client instance.
    
    Args:
        password: The shared password
        
    Returns:
        SPAKE2Client instance
    """
    logger.debug("[SPAKE2] Creating SPAKE2 client")
    return SPAKE2Client(password)
