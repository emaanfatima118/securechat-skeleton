"""
transcript.py - Transcript Management Module
Handles session transcript logging for non-repudiation
"""

import os
import json
from datetime import datetime
from app.common.utils import ensure_directory, format_transcript_line
from app.crypto.sign import sha256_hash, rsa_sign  
from app.crypto.pki import get_cert_fingerprint

class TranscriptManager:
    """Manages append-only transcript for non-repudiation"""
    
    def __init__(self, username: str, peer_type: str):
        """
        Initialize transcript manager
        
        Args:
            username: username for filename
            peer_type: 'client' or 'server'
        """
        self.username = username
        self.peer_type = peer_type
        self.transcript = []
        
        # Create transcript filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ensure_directory("transcripts")
        self.transcript_file = f"transcripts/{peer_type}_{username}_{timestamp}.txt"
        
    def log_message(self, seqno: int, ts: int, ct: str, sig: str, 
                   peer_cert) -> None:
        """
        Log message to transcript
        
        Args:
            seqno: sequence number
            ts: timestamp
            ct: ciphertext (base64)
            sig: signature (base64)
            peer_cert: peer's certificate object
        """
        peer_fp = get_cert_fingerprint(peer_cert)
        line = format_transcript_line(seqno, ts, ct, sig, peer_fp)
        
        self.transcript.append(line)
        
        # Append to file
        with open(self.transcript_file, 'a') as f:
            f.write(line)
    
    def generate_receipt(self, private_key) -> dict:
        """
        Generate session receipt with signed transcript hash
        
        Args:
            private_key: RSA private key for signing
        
        Returns:
            Receipt dictionary
        """
        if not self.transcript:
            return None
        
        # Compute transcript hash
        transcript_data = ''.join(self.transcript)
        transcript_hash = sha256_hash(transcript_data)
        
        # Sign transcript hash
        sig = rsa_sign(transcript_hash.encode('utf-8'), private_key)
        
        receipt = {
            "type": "receipt",
            "peer": self.peer_type,
            "first_seq": 0,
            "last_seq": len(self.transcript) - 1,
            "transcript_sha256": transcript_hash,
            "sig": sig
        }
        
        # Save receipt to file
        receipt_file = self.transcript_file.replace('.txt', '_receipt.json')
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[+] Receipt saved: {receipt_file}")
        
        return receipt
    
    def save_peer_receipt(self, receipt: dict) -> None:
        """
        Save peer's receipt
        
        Args:
            receipt: receipt dictionary from peer
        """
        receipt_file = self.transcript_file.replace('.txt', '_peer_receipt.json')
        with open(receipt_file, 'w') as f:
            json.dump(receipt, f, indent=2)
        
        print(f"[+] Peer receipt saved: {receipt_file}")