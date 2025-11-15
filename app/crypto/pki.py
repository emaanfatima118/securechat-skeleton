"""
pki.py - PKI and Certificate Operations Module
Handles certificate loading, validation, and operations
"""

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

def load_certificate(cert_path: str):
    """
    Load X.509 certificate from PEM file
    
    Args:
        cert_path: path to certificate file
    
    Returns:
        Certificate object
    """
    with open(cert_path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_private_key(key_path: str):
    """
    Load RSA private key from PEM file
    
    Args:
        key_path: path to private key file
    
    Returns:
        RSA private key object
    """
    with open(key_path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )

def cert_to_pem_string(cert) -> str:
    """
    Convert certificate object to PEM string
    
    Args:
        cert: certificate object
    
    Returns:
        PEM-encoded certificate string
    """
    return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')

def pem_string_to_cert(pem_string: str):
    """
    Convert PEM string to certificate object
    
    Args:
        pem_string: PEM-encoded certificate
    
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(
        pem_string.encode('ascii'),
        default_backend()
    )

def get_cert_fingerprint(cert) -> str:
    """
    Get SHA-256 fingerprint of certificate
    
    Args:
        cert: certificate object
    
    Returns:
        Hex string of fingerprint
    """
    return cert.fingerprint(hashes.SHA256()).hex()

def verify_certificate(cert, ca_cert) -> tuple:
    """
    Verify certificate signature and validity
    
    Checks:
    1. Signature chain validity (signed by trusted CA)
    2. Expiry date and validity period
    3. Certificate not expired or not yet valid
    
    Args:
        cert: certificate to verify
        ca_cert: CA certificate (issuer)
    
    Returns:
        (is_valid: bool, error_message: str) tuple
    """
    # Check if certificate is expired or not yet valid
    now = datetime.datetime.utcnow()
    
    if now < cert.not_valid_before:
        return False, "Certificate not yet valid"
    
    if now > cert.not_valid_after:
        return False, "Certificate expired"
    
    # Verify signature chain
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
    except Exception as e:
        return False, f"Signature verification failed: {str(e)}"
    
    # Verify issuer matches CA subject
    if cert.issuer != ca_cert.subject:
        return False, "Certificate issuer does not match CA"
    
    return True, "OK"

def verify_hostname(cert, expected_hostname: str) -> bool:
    """
    Verify certificate Common Name (CN) matches expected hostname
    
    Args:
        cert: certificate to check
        expected_hostname: expected CN value
    
    Returns:
        True if matches, False otherwise
    """
    # Get CN from subject
    cn_list = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    
    if not cn_list:
        return False
    
    cn = cn_list[0].value
    
    # Simple exact match (production would check SANs too)
    return cn == expected_hostname