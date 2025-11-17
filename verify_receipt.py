#!/usr/bin/env python3
"""
verify_receipt.py - Offline Receipt Verification
Verifies transcript integrity and signature authenticity
"""

import json
import sys
from app.crypto.sign import sha256_hash, rsa_verify
from app.crypto.pki import load_certificate

def verify_receipt(transcript_file, receipt_file, cert_file):
    """Verify a session receipt against its transcript"""
    
    print("="*70)
    print("SESSION RECEIPT VERIFICATION")
    print("="*70)
    
    # Load transcript
    print(f"\n[1] Loading transcript: {transcript_file}")
    try:
        with open(transcript_file, 'r') as f:
            transcript_data = f.read()
        print(f"    ✓ Loaded {len(transcript_data)} bytes")
        print(f"    ✓ Contains {len(transcript_data.splitlines())} messages")
    except FileNotFoundError:
        print(f"    ✗ Error: File not found")
        return False
    
    # Load receipt
    print(f"\n[2] Loading receipt: {receipt_file}")
    try:
        with open(receipt_file, 'r') as f:
            receipt = json.load(f)
        print(f"    ✓ Receipt type: {receipt['type']}")
        print(f"    ✓ Peer: {receipt['peer']}")
        print(f"    ✓ Message range: {receipt['first_seq']} to {receipt['last_seq']}")
        print(f"    ✓ Transcript hash: {receipt['transcript_sha256'][:32]}...")
    except FileNotFoundError:
        print(f"    ✗ Error: File not found")
        return False
    except json.JSONDecodeError:
        print(f"    ✗ Error: Invalid JSON")
        return False
    
    # Load certificate
    print(f"\n[3] Loading certificate: {cert_file}")
    try:
        cert = load_certificate(cert_file)
        print(f"    ✓ Certificate: {cert.subject.rfc4514_string()}")
    except FileNotFoundError:
        print(f"    ✗ Error: File not found")
        return False
    
    # Verify transcript hash
    print(f"\n[4] Verifying transcript hash...")
    computed_hash = sha256_hash(transcript_data)
    receipt_hash = receipt['transcript_sha256']
    
    print(f"    Computed: {computed_hash}")
    print(f"    Receipt:  {receipt_hash}")
    
    if computed_hash == receipt_hash:
        print(f"    ✓ HASH MATCH - Transcript integrity verified")
        hash_valid = True
    else:
        print(f"    ✗ HASH MISMATCH - Transcript has been tampered!")
        hash_valid = False
    
    # Verify signature
    print(f"\n[5] Verifying RSA signature...")
    public_key = cert.public_key()
    signature = receipt['sig']
    
    is_valid = rsa_verify(
        receipt_hash.encode('utf-8'),
        signature,
        public_key
    )
    
    if is_valid:
        print(f"    ✓ SIGNATURE VALID - Authenticity confirmed")
        sig_valid = True
    else:
        print(f"    ✗ SIGNATURE INVALID - Receipt may be forged!")
        sig_valid = False
    
    # Verify individual messages
    print(f"\n[6] Verifying individual message signatures...")
    lines = transcript_data.strip().split('\n')
    all_valid = True
    
    for i, line in enumerate(lines[:3]):  # Check first 3 messages
        parts = line.split('|')
        if len(parts) != 5:
            continue
        
        seqno, ts, ct, sig, fp = parts
        data_to_verify = f"{seqno}||{ts}||{ct}".encode('utf-8')
        
        if rsa_verify(data_to_verify, sig, public_key):
            print(f"    ✓ Message {seqno}: Signature valid")
        else:
            print(f"    ✗ Message {seqno}: Signature INVALID")
            all_valid = False
    
    if len(lines) > 3:
        print(f"    ... ({len(lines)-3} more messages)")
    
    # Final verdict
    print("\n" + "="*70)
    print("VERIFICATION RESULT")
    print("="*70)
    
    if hash_valid and sig_valid and all_valid:
        print("✓✓✓ RECEIPT FULLY VERIFIED")
        print("\nThis receipt provides cryptographic proof of:")
        print("  • Message integrity (no tampering)")
        print("  • Sender authenticity (valid signature)")
        print("  • Non-repudiation (sender cannot deny)")
        return True
    else:
        print("✗✗✗ VERIFICATION FAILED")
        if not hash_valid:
            print("  • Transcript hash mismatch")
        if not sig_valid:
            print("  • Receipt signature invalid")
        if not all_valid:
            print("  • Some message signatures invalid")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python verify_receipt.py <transcript> <receipt> <certificate>")
        print("\nExample:")
        print("  python verify_receipt.py \\")
        print("    transcripts/client_i220869_20251115_123000.txt \\")
        print("    transcripts/client_i220869_20251115_123000_receipt.json \\")
        print("    certs/client_cert.pem")
        sys.exit(1)
    
    transcript = sys.argv[1]
    receipt = sys.argv[2]
    cert = sys.argv[3]
    
    result = verify_receipt(transcript, receipt, cert)
    sys.exit(0 if result else 1)