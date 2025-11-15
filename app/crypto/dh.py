"""
dh.py - Diffie-Hellman Key Exchange Module
Implements classical DH key exchange with standard parameters
"""

import os
import hashlib

# Standard 1536-bit MODP group (RFC 3526)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF", 16
)

DH_G = 2

def generate_keypair() -> tuple:
    """
    Generate DH private key and compute public key
    
    Returns:
        (private_key, public_key) tuple
    """
    # Generate random private key (256 bits)
    private_key = int.from_bytes(os.urandom(32), byteorder='big')
    
    # Compute public key: g^a mod p
    public_key = pow(DH_G, private_key, DH_P)
    
    return private_key, public_key

def compute_shared_secret(private_key: int, peer_public_key: int) -> int:
    """
    Compute shared secret from peer's public key
    
    Args:
        private_key: our private DH key
        peer_public_key: peer's public DH key (A or B)
    
    Returns:
        shared secret K_s = peer_public^private mod p
    """
    return pow(peer_public_key, private_key, DH_P)

def derive_aes_key(shared_secret: int) -> bytes:
    """
    Derive AES-128 key from DH shared secret
    
    K = Trunc_16(SHA256(big-endian(K_s)))
    
    Args:
        shared_secret: integer shared secret from DH
    
    Returns:
        16-byte AES-128 key
    """
    # Convert shared secret to big-endian bytes
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, 
        byteorder='big'
    )
    
    # Hash with SHA-256
    h = hashlib.sha256(secret_bytes).digest()
    
    # Truncate to 16 bytes for AES-128
    return h[:16]

def get_dh_params() -> tuple:
    """
    Get standard DH parameters
    
    Returns:
        (g, p) tuple
    """
    return DH_G, DH_P