"""
utils.py - Utility Functions
Helper functions for file I/O and data handling
"""

import os
import time
import base64
import hashlib

def now_ms():
    """Return current Unix timestamp in milliseconds."""
    return int(time.time() * 1000)

def b64e(b: bytes):
    """Base64 encode bytes to string."""
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str):
    """Base64 decode string to bytes."""
    return base64.b64decode(s)

def sha256_hex(data: bytes):
    """Compute SHA-256 hash and return hex string."""
    return hashlib.sha256(data).hexdigest()

def ensure_directory(path: str):
    """Create directory if it doesn't exist"""
    os.makedirs(path, exist_ok=True)

def generate_nonce(size: int = 32) -> str:
    """Generate random nonce and return as base64 string"""
    return b64e(os.urandom(size))

def get_timestamp() -> int:
    """Get current Unix timestamp in milliseconds"""
    return now_ms()

def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks
    
    Args:
        a, b: strings to compare
    
    Returns:
        True if equal, False otherwise
    """
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def format_transcript_line(seqno: int, ts: int, ct: str, sig: str, 
                          peer_fingerprint: str) -> str:
    """
    Format transcript line according to spec:
    seqno | ts | ct | sig | peer-cert-fingerprint
    """
    return f"{seqno}|{ts}|{ct}|{sig}|{peer_fingerprint}\n"

def parse_transcript_line(line: str) -> tuple:
    """Parse transcript line into components"""
    parts = line.strip().split('|')
    if len(parts) != 5:
        raise ValueError("Invalid transcript format")
    
    seqno = int(parts[0])
    ts = int(parts[1])
    ct = parts[2]
    sig = parts[3]
    fingerprint = parts[4]
    
    return seqno, ts, ct, sig, fingerprint