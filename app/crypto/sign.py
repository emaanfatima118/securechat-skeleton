"""
sign.py - RSA Signature Operations Module
Implements RSA signing and verification with SHA-256
"""

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from app.common.utils import b64e, b64d, sha256_hex

def sha256_hash(data) -> str:
    """
    Compute SHA-256 hash of data
    
    Args:
        data: bytes or string to hash
    
    Returns:
        Hex string of hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return sha256_hex(data)

def sha256_hash_bytes(data) -> bytes:
    """
    Compute SHA-256 hash of data, return bytes
    
    Args:
        data: bytes or string to hash
    
    Returns:
        32-byte hash
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def rsa_sign(data, private_key) -> str:
    """
    Sign data with RSA private key using SHA-256
    
    Args:
        data: bytes to sign
        private_key: RSA private key object
    
    Returns:
        base64-encoded signature
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return b64e(signature)  # ✅ Use b64e

def rsa_verify(data, signature_b64: str, public_key) -> bool:
    """
    Verify RSA signature
    
    Args:
        data: bytes that were signed
        signature_b64: base64-encoded signature
        public_key: RSA public key object
    
    Returns:
        True if valid, False otherwise
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    try:
        signature = b64d(signature_b64)  # ✅ Use b64d
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def hash_password(password: str, salt: bytes) -> str:
    """
    Hash password with salt: SHA256(salt || password)
    
    Args:
        password: plaintext password
        salt: 16-byte salt
    
    Returns:
        Hex string of hash (64 characters)
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    return hashlib.sha256(salt + password).hexdigest()