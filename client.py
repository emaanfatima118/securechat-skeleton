#!/usr/bin/env python3
"""
client.py - Secure Chat Client
Connects to server, authenticates, and exchanges encrypted messages
"""

import socket
import sys
import os
import json
import time
import getpass
import threading

# Import application modules
from app.common.protocol import Protocol
from app.common.utils import generate_nonce, get_timestamp, b64e, b64d
from app.crypto import aes, dh, pki, sign
from app.storage.transcript import TranscriptManager

# Configuration
HOST = '127.0.0.1'
PORT = 5000
CA_CERT_PATH = "certs/ca_cert.pem"
CLIENT_CERT_PATH = "certs/client_cert.pem"
CLIENT_KEY_PATH = "certs/client_key.pem"

class SecureChatClient:
    """Secure Chat Client"""
    
    def __init__(self):
        self.sock = None
        
        # Load certificates
        self.ca_cert = pki.load_certificate(CA_CERT_PATH)
        self.client_cert = pki.load_certificate(CLIENT_CERT_PATH)
        self.client_key = pki.load_private_key(CLIENT_KEY_PATH)
        
        # Session state
        self.server_cert = None
        self.session_key = None
        self.username = None
        
        # Message tracking
        self.last_seqno = -1
        self.transcript_mgr = None
        self.running = True

        self.saved_message = None 

        
    def connect(self) -> bool:
        """Connect to server"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.sock.connect((HOST, PORT))
            print(f"[+] Connected to {HOST}:{PORT}")
            return True
        except Exception as e:
            print(f"[!] Connection failed: {e}")
            return False
    
    def control_plane(self) -> bool:
        """
        Phase 1: Control Plane - Certificate exchange and authentication
        
        Returns:
            True if successful
        """
        print("\n[*] Control Plane: Certificate exchange and authentication")
        
        # Step 1: Send client hello
        client_nonce = generate_nonce()
        Protocol.send_message(self.sock, Protocol.create_hello(
            pki.cert_to_pem_string(self.client_cert),
            client_nonce
        ))
        
        # Step 2: Receive server hello
        msg = Protocol.recv_message(self.sock)
        if not msg or msg.get('type') == 'error':
            print(f"[!] Server rejected certificate: {msg.get('message', 'Unknown error')}")
            return False
        
        if msg['type'] != 'server_hello':
            print("[!] Invalid server response")
            return False
        
        # Step 3: Verify server certificate
        try:
            server_cert_pem = msg['server_cert']
            self.server_cert = pki.pem_string_to_cert(server_cert_pem)
            
            is_valid, error = pki.verify_certificate(self.server_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] BAD_CERT: {error}")
                return False
            
            # Verify hostname
            if not pki.verify_hostname(self.server_cert, "localhost"):
                print("[!] BAD_CERT: Hostname mismatch")
                return False
            
            print(f"[+] Server certificate verified: {self.server_cert.subject.rfc4514_string()}")
            
        except Exception as e:
            print(f"[!] Certificate verification failed: {e}")
            return False
        
        # Step 4: Temporary DH exchange for control plane
        temp_private, temp_public = dh.generate_keypair()
        
        # Receive server DH
        dh_msg = Protocol.recv_message(self.sock)
        if not dh_msg or dh_msg.get('type') != 'dh_server_control':
            return False
        
        server_B = dh_msg['B']
        
        # Send client DH
        Protocol.send_message(self.sock, {
            "type": "dh_client_control",
            "A": temp_public
        })
        
        # Derive temporary AES key
        shared_secret = dh.compute_shared_secret(temp_private, server_B)
        temp_key = dh.derive_aes_key(shared_secret)
        
        # Step 5: Authenticate
        return self.authenticate(temp_key)
    
    def authenticate(self, temp_key: bytes) -> bool:
        """Handle registration or login"""
        print("\n=== Authentication ===")
        print("1. Register")
        print("2. Login")
        choice = input("Choose (1/2): ").strip()
        
        if choice == '1':
            return self.register(temp_key)
        elif choice == '2':
            return self.login(temp_key)
        else:
            print("[!] Invalid choice")
            return False
    
    def register(self, temp_key: bytes) -> bool:
        """Register new user"""
        print("\n=== Registration ===")
        email = input("Email: ").strip()
        username = input("Username: ").strip()
        password = getpass.getpass("Password: ")
        
        # Prepare registration data (send plaintext password encrypted)
        reg_data = {
            "email": email,
            "username": username,
            "password": password  # Server will salt and hash
        }
        
        # Encrypt and send
        encrypted = aes.aes_encrypt(json.dumps(reg_data).encode('utf-8'), temp_key)
        Protocol.send_message(self.sock, {
            "type": "register",
            "data": encrypted
        })
        
        # Receive response
        response = Protocol.recv_message(self.sock)
        if response and response.get('success'):
            print(f"[+] {response['message']}")
            self.username = username
            return True
        else:
            print(f"[!] Registration failed: {response.get('message', 'Unknown error')}")
            return False
    
    def login(self, temp_key: bytes) -> bool:
        """Login existing user"""
        print("\n=== Login ===")
        email = input("Email: ").strip()
        
        # Prepare login request
        login_data = {
            "email": email
        }
        
        # Encrypt and send
        encrypted = aes.aes_encrypt(json.dumps(login_data).encode('utf-8'), temp_key)
        Protocol.send_message(self.sock, {
            "type": "login",
            "data": encrypted
        })
        
        # Receive salt
        salt_msg = Protocol.recv_message(self.sock)
        if not salt_msg or salt_msg.get('type') != 'salt_response':
            print("[!] Failed to get salt")
            return False
        
        # Get password
        password = getpass.getpass("Password: ")
        
        # Send encrypted password
        encrypted_pwd = aes.aes_encrypt(password.encode('utf-8'), temp_key)
        Protocol.send_message(self.sock, {
            "type": "pwd_hash",
            "encrypted_pwd": encrypted_pwd
        })
        
        # Receive response
        response = Protocol.recv_message(self.sock)
        if response and response.get('success'):
            print(f"[+] {response['message']}")
            self.username = response['username']
            return True
        else:
            print(f"[!] Login failed: {response.get('message', 'Unknown error')}")
            return False
    
    def key_agreement(self) -> bool:
        """
        Phase 2: Key Agreement - DH key exchange for session
        
        Returns:
            True if successful
        """
        print("\n[*] Key Agreement: Establishing session key")
        
        # Generate client DH keypair
        self.dh_private, self.dh_public = dh.generate_keypair()
        
        # Send DH parameters to server
        g, p = dh.get_dh_params()
        Protocol.send_message(self.sock, Protocol.create_dh_client(g, p, self.dh_public))
        
        # Receive server DH
        dh_msg = Protocol.recv_message(self.sock)
        if not dh_msg or dh_msg.get('type') != 'dh_server':
            return False
        
        server_B = dh_msg['B']
        
        # Compute shared secret and derive session key
        shared_secret = dh.compute_shared_secret(self.dh_private, server_B)
        self.session_key = dh.derive_aes_key(shared_secret)
        
        print(f"[+] Session key established: {self.session_key.hex()[:16]}...")
        
        # Initialize transcript manager
        self.transcript_mgr = TranscriptManager(self.username, "client")
        
        return True
    
    def data_plane(self):
        """Phase 3: Data Plane - Encrypted message exchange"""
        print("\n[*] Data Plane: Encrypted messaging")
        print("[*] Type '/quit' to exit\n")
        
        # Start receiver thread
        receiver_thread = threading.Thread(target=self.receive_messages)
        receiver_thread.daemon = True
        receiver_thread.start()
        
        # Send messages
        while self.running:
            try:
                message = input(f"{self.username}: ")
                
                if message.lower() == '/quit':
                    Protocol.send_message(self.sock, {"type": "quit"})
                    self.running = False
                    break
                
                if message.strip():
                    self.send_message(message)
                    
            except KeyboardInterrupt:
                print("\n[*] Exiting...")
                self.running = False
                break
            except Exception as e:
                print(f"[!] Error: {e}")
                break
        
        # Wait for final messages
        time.sleep(1)
    
    def send_message(self, plaintext: str):
        """Send encrypted and signed message"""
        seqno = len(self.transcript_mgr.transcript)
        ts = get_timestamp()
        
        # Encrypt message
        ct = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        
        # Sign: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_sign = f"{seqno}||{ts}||{ct}".encode('utf-8')
        
        # ADD DEBUG OUTPUT
        # print(f"[DEBUG CLIENT] seqno={seqno}, ts={ts}")
        # print(f"[DEBUG CLIENT] ct[:50]={ct[:50]}")
        # print(f"[DEBUG CLIENT] data_to_sign[:100]={data_to_sign[:100]}")
        
        sig = sign.rsa_sign(data_to_sign, self.client_key)
        
        # print(f"[DEBUG CLIENT] sig[:50]={sig[:50]}")
        
        msg = Protocol.create_encrypted_message(seqno, ts, ct, sig)
        Protocol.send_message(self.sock, msg)
        
        # Log to transcript
        self.transcript_mgr.log_message(seqno, ts, ct, sig, self.client_cert)


# tampering test
    # def send_message(self, plaintext: str):
    #     """Send encrypted and signed message"""
    #     seqno = len(self.transcript_mgr.transcript)
    #     ts = get_timestamp()
        
    #     # Encrypt message
    #     ct = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        
    #     # TAMPER: Corrupt the ciphertext (flip last character)
    #     if plaintext.startswith("TAMPER"):
    #         print("[!] TAMPERING: Corrupting ciphertext...")
    #         ct = ct[:-1] + ('X' if ct[-1] != 'X' else 'Y')
        
    #     # Sign: RSA_SIGN(SHA256(seqno||ts||ct))
    #     data_to_sign = f"{seqno}||{ts}||{ct}".encode('utf-8')
    #     sig = sign.rsa_sign(data_to_sign, self.client_key)
        
    #     msg = Protocol.create_encrypted_message(seqno, ts, ct, sig)
    #     Protocol.send_message(self.sock, msg)
        
    #     # Log to transcript
    #     self.transcript_mgr.log_message(seqno, ts, ct, sig, self.client_cert)
# replay attack testing
# add self.saved_message = None  (to init)
    # def send_message(self, plaintext: str):
        """Send encrypted and signed message"""
        
        # REPLAY: If user types REPLAY, resend the saved message
        if plaintext == "REPLAY":
            if hasattr(self, 'saved_message') and self.saved_message:
                print("[!] REPLAYING old message...")
                Protocol.send_message(self.sock, self.saved_message)
                # Don't log to transcript - we're replaying, not creating new
                return
            else:
                print("[!] No saved message to replay")
                return
        
        # Normal flow: Create new message
        seqno = len(self.transcript_mgr.transcript)
        ts = get_timestamp()
        
        # Encrypt message
        ct = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        
        # Sign: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_sign = f"{seqno}||{ts}||{ct}".encode('utf-8')
        sig = sign.rsa_sign(data_to_sign, self.client_key)
        
        msg = Protocol.create_encrypted_message(seqno, ts, ct, sig)
        
        # SAVE: If user types SAVE, save this message for replay
        if plaintext == "SAVE":
            self.saved_message = msg
            print("[!] Message saved for replay")
        
        # Send message
        Protocol.send_message(self.sock, msg)
        
        # Log to transcript
        self.transcript_mgr.log_message(seqno, ts, ct, sig, self.client_cert)

      
# Tamper testing
    # def send_message(self, plaintext: str):
        """Send encrypted and signed message"""
        seqno = len(self.transcript_mgr.transcript)
        ts = get_timestamp()
        
        # Encrypt message
        ct = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        
        # TAMPER: Corrupt the ciphertext (flip last character)
        if plaintext.startswith("TAMPER"):
            print("[!] TAMPERING: Corrupting ciphertext...")
            ct = ct[:-1] + ('X' if ct[-1] != 'X' else 'Y')
        
        # Sign: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_sign = f"{seqno}||{ts}||{ct}".encode('utf-8')
        sig = sign.rsa_sign(data_to_sign, self.client_key)
        
        msg = Protocol.create_encrypted_message(seqno, ts, ct, sig)
        Protocol.send_message(self.sock, msg)
        
        # Log to transcript
        self.transcript_mgr.log_message(seqno, ts, ct, sig, self.client_cert)
    def receive_messages(self):
        """Receive and decrypt messages from server"""
        while self.running:
            try:
                msg = Protocol.recv_message(self.sock)
                if not msg:
                    break
                
                if msg['type'] == 'msg':
                    if not self.verify_message(msg):
                        print("\n[!] Message verification failed")
                        continue
                    
                    # Decrypt message
                    plaintext = aes.aes_decrypt(msg['ct'], self.session_key)
                    print(f"\nServer: {plaintext.decode('utf-8')}")
                    print(f"{self.username}: ", end='', flush=True)
                    
                    # Log to transcript
                    self.transcript_mgr.log_message(
                        msg['seqno'], msg['ts'], msg['ct'],
                        msg['sig'], self.server_cert
                    )
                
                elif msg['type'] == 'receipt':
                    self.transcript_mgr.save_peer_receipt(msg)
                    break
                    
            except Exception as e:
                if self.running:
                    print(f"\n[!] Receive error: {e}")
                break
    
    def verify_message(self, msg: dict) -> bool:
        """
        Verify message integrity and authenticity
        
        Args:
            msg: message dictionary
        
        Returns:
            True if valid, False otherwise
        """
        seqno = msg['seqno']
        ts = msg['ts']
        ct = msg['ct']
        sig = msg['sig']
        
        # Check sequence number (replay protection)
        if seqno <= self.last_seqno:
            print(f"\n[!] REPLAY: seqno {seqno} <= {self.last_seqno}")
            return False
        
        # Check timestamp (within 5 minutes)
        current_ts = get_timestamp()
        if abs(current_ts - ts) > 300000:
            print(f"\n[!] Timestamp too old/future")
            return False
        
        # Verify signature: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_verify = f"{seqno}||{ts}||{ct}".encode('utf-8')
        server_public_key = self.server_cert.public_key()
        
        if not sign.rsa_verify(data_to_verify, sig, server_public_key):
            print(f"\n[!] SIG_FAIL")
            return False
        
        self.last_seqno = seqno
        return True
    
    def teardown(self):
        """Phase 4: Teardown - Generate and exchange receipts"""
        print("\n[*] Teardown: Generating non-repudiation receipt")
        
        if not self.transcript_mgr or not self.transcript_mgr.transcript:
            print("[!] No messages exchanged, skipping receipt generation")
            return
        
        # Generate receipt
        receipt = self.transcript_mgr.generate_receipt(self.client_key)
        
        if not receipt:
            print("[!] Failed to generate receipt")
            return
        
        # Send receipt to server
        try:
            Protocol.send_message(self.sock, receipt)
            print("[+] Receipt sent to server")
        except Exception as e:
            print(f"[!] Failed to send receipt: {e}")
        
        # Try to receive server receipt (may already have it from receive thread)
        try:
            self.sock.settimeout(2.0)  # Wait 2 seconds
            server_receipt = Protocol.recv_message(self.sock)
            if server_receipt and server_receipt.get('type') == 'receipt':
                self.transcript_mgr.save_peer_receipt(server_receipt)
        except Exception as e:
            print(f"[!] Could not receive server receipt (may already have it)")
    def run(self):
        """Main client flow"""
        print("="*60)
        print("SECURE CHAT CLIENT")
        print("="*60)
        
        try:
            # Connect
            if not self.connect():
                return
            
            # Phase 1: Control Plane
            if not self.control_plane():
                return
            
            # Phase 2: Key Agreement
            if not self.key_agreement():
                return
            
            # Phase 3: Data Plane
            self.data_plane()
            
            # Phase 4: Teardown
            self.teardown()
            
        except Exception as e:
            print(f"[!] Error: {e}")
        
        finally:
            if self.sock:
                self.sock.close()
            print("\n[*] Disconnected")

def main():
    """Main function"""
    if not os.path.exists(CLIENT_CERT_PATH):
        print("[!] Client certificate not found. Run: python scripts/gen_ca.py && python scripts/gen_cert.py")
        return
    
    client = SecureChatClient()
    client.run()

if __name__ == "__main__":
    main()