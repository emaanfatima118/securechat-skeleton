"""
aes.py - AES-128 Encryption Module
Implements AES-128 in CBC mode with PKCS#7 padding
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from app.common.utils import b64e, b64d

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Apply PKCS#7 padding to data
    
    Args:
        data: bytes to pad
        block_size: block size (16 for AES)
    
    Returns:
        Padded data
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    """
    Remove PKCS#7 padding from data
    
    Args:
        data: padded bytes
    
    Returns:
        Unpadded data
    
    Raises:
        ValueError: if padding is invalid
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    padding_length = data[-1]
    
    if padding_length > len(data) or padding_length > 16:
        raise ValueError("Invalid padding length")
    
    # Verify all padding bytes are correct
    for i in range(padding_length):
        if data[-1 - i] != padding_length:
            raise ValueError("Invalid padding bytes")
    
    return data[:-padding_length]

def aes_encrypt(plaintext: bytes, key: bytes) -> str:
    """
    Encrypt plaintext using AES-128 CBC with PKCS#7 padding
    
    Args:
        plaintext: bytes to encrypt
        key: 16-byte AES key
    
    Returns:
        base64-encoded string of (IV + ciphertext)
    """
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Generate random IV
    iv = os.urandom(16)
    
    # Pad plaintext
    padded = pkcs7_pad(plaintext, 16)
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    
    # Return IV + ciphertext as base64
    return b64e(iv + ciphertext)

def aes_decrypt(ciphertext_b64: str, key: bytes) -> bytes:
    """
    Decrypt AES-128 CBC ciphertext
    
    Args:
        ciphertext_b64: base64-encoded (IV + ciphertext)
        key: 16-byte AES key
    
    Returns:
        Decrypted plaintext bytes
    """
    if len(key) != 16:
        raise ValueError("AES-128 requires 16-byte key")
    
    # Decode from base64
    data = b64d(ciphertext_b64)
    
    if len(data) < 32:  # At least IV + one block
        raise ValueError("Ciphertext too short")
    
    # Extract IV and ciphertext
    iv = data[:16]
    ciphertext = data[16:]
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding
    plaintext = pkcs7_unpad(padded_plaintext)
    
    return plaintext