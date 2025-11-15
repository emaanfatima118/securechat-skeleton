import socket
import sys
import os
import json
import time
import threading

# Import application modules
from app.common.protocol import Protocol
from app.common.utils import generate_nonce, get_timestamp, b64e, b64d
from app.crypto import aes, dh, pki, sign
from app.storage.db import init_database, register_user, get_user_salt, verify_login
from app.storage.transcript import TranscriptManager

# Configuration
HOST = '127.0.0.1'
PORT = 5000
CA_CERT_PATH = "certs/ca_cert.pem"
SERVER_CERT_PATH = "certs/server_cert.pem"
SERVER_KEY_PATH = "certs/server_key.pem"

class ClientHandler:
    """Handles individual client connection"""
    
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        
        # Load certificates
        self.ca_cert = pki.load_certificate(CA_CERT_PATH)
        self.server_cert = pki.load_certificate(SERVER_CERT_PATH)
        self.server_key = pki.load_private_key(SERVER_KEY_PATH)
        
        # Session state
        self.client_cert = None
        self.session_key = None
        self.username = None
        self.authenticated = False
        
        # Message tracking
        self.last_seqno = -1
        self.transcript_mgr = None
        
    def handle(self):
        """Main handler for client connection"""
        try:
            print(f"\n[+] New connection from {self.addr}")
            
            # Phase 1: Control Plane (Negotiation and Authentication)
            if not self.control_plane():
                return
            
            # Phase 2: Key Agreement (Session Key)
            if not self.key_agreement():
                return
            
            # Phase 3: Data Plane (Encrypted Messaging)
            self.data_plane()
            
            # Phase 4: Teardown (Non-Repudiation)
            self.teardown()
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            self.conn.close()
            print(f"[*] Connection closed: {self.addr}")
    
    def control_plane(self) -> bool:
        """
        Phase 1: Control Plane - Certificate exchange and authentication
        
        Returns:
            True if successful, False otherwise
        """
        print("[*] Control Plane: Certificate exchange and authentication")
        
        # Step 1: Receive client hello
        msg = Protocol.recv_message(self.conn)
        if not msg or msg.get('type') != 'hello':
            print("[!] Invalid hello message")
            return False
        
        # Step 2: Verify client certificate
        try:
            client_cert_pem = msg['client_cert']
            self.client_cert = pki.pem_string_to_cert(client_cert_pem)
            
            is_valid, error = pki.verify_certificate(self.client_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] BAD_CERT: {error}")
                Protocol.send_message(self.conn, {"type": "error", "message": "BAD_CERT"})
                return False
            
            print(f"[+] Client certificate verified: {self.client_cert.subject.rfc4514_string()}")
            
        except Exception as e:
            print(f"[!] Certificate verification failed: {e}")
            Protocol.send_message(self.conn, {"type": "error", "message": "BAD_CERT"})
            return False
        
        # Step 3: Send server hello
        server_nonce = generate_nonce()
        Protocol.send_message(self.conn, Protocol.create_server_hello(
            pki.cert_to_pem_string(self.server_cert),
            server_nonce
        ))
        
        # Step 4: Temporary DH exchange for control plane encryption
        temp_private, temp_public = dh.generate_keypair()
        
        Protocol.send_message(self.conn, {
            "type": "dh_server_control",
            "B": temp_public
        })
        
        # Receive client DH
        dh_msg = Protocol.recv_message(self.conn)
        if not dh_msg or dh_msg.get('type') != 'dh_client_control':
            return False
        
        client_A = dh_msg['A']
        
        # Derive temporary AES key
        shared_secret = dh.compute_shared_secret(temp_private, client_A)
        temp_key = dh.derive_aes_key(shared_secret)
        
        # Step 5: Receive encrypted authentication message
        auth_msg = Protocol.recv_message(self.conn)
        if not auth_msg:
            return False
        
        try:
            auth_type = auth_msg['type']
            encrypted_data = auth_msg['data']
            
            # Decrypt authentication data
            decrypted = aes.aes_decrypt(encrypted_data, temp_key)
            auth_data = json.loads(decrypted.decode('utf-8'))
            
            if auth_type == 'register':
                return self.handle_registration(auth_data)
            elif auth_type == 'login':
                return self.handle_login(auth_data, temp_key)
            else:
                return False
                
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return False
    
    def handle_registration(self, data: dict) -> bool:
        """Handle user registration"""
        email = data['email']
        username = data['username']
        password = data['password']
        
        # Generate salt and hash password
        salt = os.urandom(16)
        pwd_hash = sign.hash_password(password, salt)
        
        # Store in database
        success, message = register_user(email, username, salt, pwd_hash)
        
        if success:
            print(f"[+] User registered: {username} ({email})")
            Protocol.send_message(self.conn, {
                "type": "register_response",
                "success": True,
                "message": message
            })
            self.username = username
            self.authenticated = True
            return True
        else:
            print(f"[!] Registration failed: {message}")
            Protocol.send_message(self.conn, {
                "type": "register_response",
                "success": False,
                "message": message
            })
            return False
    
    def handle_login(self, data: dict, temp_key: bytes) -> bool:
        """Handle user login"""
        email = data['email']
        
        # Get salt for user
        salt = get_user_salt(email)
        if not salt:
            Protocol.send_message(self.conn, {
                "type": "login_response",
                "success": False,
                "message": "User not found"
            })
            return False
        
        # Send salt to client
        Protocol.send_message(self.conn, {
            "type": "salt_response",
            "salt": b64e(salt)
        })
        
        # Receive password hash from client
        pwd_msg = Protocol.recv_message(self.conn)
        if not pwd_msg or pwd_msg.get('type') != 'pwd_hash':
            return False
        
        # Client sends encrypted password
        encrypted_pwd = pwd_msg['encrypted_pwd']
        password = aes.aes_decrypt(encrypted_pwd, temp_key).decode('utf-8')
        
        # Compute hash
        pwd_hash = sign.hash_password(password, salt)
        
        # Verify credentials
        success, username, message = verify_login(email, pwd_hash)
        
        if success:
            print(f"[+] User logged in: {username} ({email})")
            Protocol.send_message(self.conn, {
                "type": "login_response",
                "success": True,
                "message": message,
                "username": username
            })
            self.username = username
            self.authenticated = True
            return True
        else:
            print(f"[!] Login failed: {message}")
            Protocol.send_message(self.conn, {
                "type": "login_response",
                "success": False,
                "message": message
            })
            return False
    
    def key_agreement(self) -> bool:
        """
        Phase 2: Key Agreement - DH key exchange for session
        
        Returns:
            True if successful
        """
        print("[*] Key Agreement: Establishing session key")
        
        # Generate server DH keypair
        self.dh_private, self.dh_public = dh.generate_keypair()
        
        # Send server DH public key
        Protocol.send_message(self.conn, Protocol.create_dh_server(self.dh_public))
        
        # Receive client DH
        dh_msg = Protocol.recv_message(self.conn)
        if not dh_msg or dh_msg.get('type') != 'dh_client':
            return False
        
        client_A = dh_msg['A']
        
        # Compute shared secret and derive session key
        shared_secret = dh.compute_shared_secret(self.dh_private, client_A)
        self.session_key = dh.derive_aes_key(shared_secret)
        
        print(f"[+] Session key established: {self.session_key.hex()[:16]}...")
        
        # Initialize transcript manager
        self.transcript_mgr = TranscriptManager(self.username, "server")
        
        return True
    
    def data_plane(self):
        """Phase 3: Data Plane - Encrypted message exchange"""
        print("[*] Data Plane: Encrypted messaging")
        
        while True:
            try:
                msg = Protocol.recv_message(self.conn)
                if not msg:
                    break
                
                if msg['type'] == 'msg':
                    # Verify and decrypt message
                    if not self.verify_message(msg):
                        print("[!] Message verification failed")
                        continue
                    
                    # Decrypt message
                    plaintext = aes.aes_decrypt(msg['ct'], self.session_key)
                    print(f"\n[{self.username}]: {plaintext.decode('utf-8')}")
                    
                    # Log to transcript
                    self.transcript_mgr.log_message(
                        msg['seqno'], msg['ts'], msg['ct'], 
                        msg['sig'], self.client_cert
                    )
                    
                    # Get server response
                    response = input("Server: ")
                    if response.lower() == '/quit':
                        break
                    
                    self.send_message(response)
                
                elif msg['type'] == 'quit':
                    print("[*] Client requested quit")
                    break
                    
            except Exception as e:
                print(f"[!] Data plane error: {e}")
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
            print(f"[!] REPLAY: seqno {seqno} <= {self.last_seqno}")
            return False
        
        # Check timestamp (within 5 minutes)
        current_ts = get_timestamp()
        if abs(current_ts - ts) > 300000:
            print(f"[!] Timestamp too old/future")
            return False
        
        # Verify signature: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_verify = f"{seqno}||{ts}||{ct}".encode('utf-8')
        client_public_key = self.client_cert.public_key()
        
        if not sign.rsa_verify(data_to_verify, sig, client_public_key):
            print(f"[!] SIG_FAIL")
            return False
        
        self.last_seqno = seqno
        return True
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
        
        # ADD DEBUG OUTPUT
        print(f"[DEBUG SERVER] Received: seqno={seqno}, ts={ts}")
        print(f"[DEBUG SERVER] ct[:50]={ct[:50]}")
        print(f"[DEBUG SERVER] sig[:50]={sig[:50]}")
        
        # Check sequence number (replay protection)
        if seqno <= self.last_seqno:
            print(f"[!] REPLAY: seqno {seqno} <= {self.last_seqno}")
            return False
        
        # Check timestamp (within 5 minutes)
        current_ts = get_timestamp()
        if abs(current_ts - ts) > 300000:
            print(f"[!] Timestamp too old/future")
            return False
        
        # Verify signature: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_verify = f"{seqno}||{ts}||{ct}".encode('utf-8')
        
        print(f"[DEBUG SERVER] data_to_verify[:100]={data_to_verify[:100]}")
        
        client_public_key = self.client_cert.public_key()
        
        if not sign.rsa_verify(data_to_verify, sig, client_public_key):
            print(f"[!] SIG_FAIL")
            print(f"[DEBUG SERVER] Signature verification failed!")
            return False
        
        print(f"[DEBUG SERVER] ✓ Signature VALID")
        self.last_seqno = seqno
        return True

    def send_message(self, plaintext: str):
        """Send encrypted and signed message"""
        seqno = len(self.transcript_mgr.transcript)
        ts = get_timestamp()
        
        # Encrypt message
        ct = aes.aes_encrypt(plaintext.encode('utf-8'), self.session_key)
        
        # Sign: RSA_SIGN(SHA256(seqno||ts||ct))
        data_to_sign = f"{seqno}||{ts}||{ct}".encode('utf-8')
        sig = sign.rsa_sign(data_to_sign, self.server_key)
        
        msg = Protocol.create_encrypted_message(seqno, ts, ct, sig)
        Protocol.send_message(self.conn, msg)
        
        # Log to transcript
        self.transcript_mgr.log_message(seqno, ts, ct, sig, self.server_cert)
    
    
        """Phase 4: Teardown - Generate and exchange receipts"""
        print("[*] Teardown: Generating non-repudiation receipt")
        
        if not self.transcript_mgr or not self.transcript_mgr.transcript:
            print("[!] No messages exchanged, skipping receipt generation")
            return
        
        # Generate receipt
        receipt = self.transcript_mgr.generate_receipt(self.server_key)
        
        if not receipt:
            print("[!] Failed to generate receipt")
            return
        
        # Send receipt to client
        try:
            Protocol.send_message(self.conn, receipt)
            print("[+] Receipt sent to client")
        except Exception as e:
            print(f"[!] Failed to send receipt: {e}")
        
        # Try to receive client receipt
        try:
            self.conn.settimeout(2.0)  # Wait 2 seconds for client receipt
            client_receipt = Protocol.recv_message(self.conn)
            if client_receipt and client_receipt.get('type') == 'receipt':
                self.transcript_mgr.save_peer_receipt(client_receipt)
        except Exception as e:
            print(f"[!] Failed to receive client receipt: {e}")
def main():
    """Main server function"""
    print("="*60)
    print("SECURE CHAT SERVER")
    print("="*60)
    
    # Initialize database
    print("\n[*] Initializing database...")
    if not init_database():
        print("[!] Failed to initialize database")
        return
    
    # Check certificates exist
    if not os.path.exists(SERVER_CERT_PATH):
        print("[!] Server certificate not found. Run: python scripts/gen_ca.py && python scripts/gen_cert.py")
        return
    
    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"\n[+] Server listening on {HOST}:{PORT}")
    print("[+] Waiting for connections...\n")
    
    try:
        while True:
            conn, addr = server.accept()
            
            # Handle client in separate thread
            handler = ClientHandler(conn, addr)
            client_thread = threading.Thread(target=handler.handle)
            client_thread.start()
    
    except KeyboardInterrupt:
        print("\n\n[*] Server shutting down...")
    
    finally:
        server.close()

if __name__ == "__main__":
    main()