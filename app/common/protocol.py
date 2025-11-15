"""
protocol.py - Secure Chat Protocol Message Handling
Handles JSON message serialization and socket communication
"""

import json
import socket

class Protocol:
    """Handles message serialization and socket communication"""
    
    @staticmethod
    def send_message(sock: socket.socket, data: dict):
        """
        Send JSON message over socket with length prefix
        
        Args:
            sock: socket to send on
            data: dictionary to send as JSON
        """
        msg = json.dumps(data).encode('utf-8')
        length = len(msg).to_bytes(4, 'big')
        sock.sendall(length + msg)
    
    @staticmethod
    def recv_message(sock: socket.socket) -> dict:
        """
        Receive JSON message from socket with length prefix
        
        Args:
            sock: socket to receive from
            
        Returns:
            Parsed JSON dictionary or None on error
        """
        try:
            # Receive 4-byte length prefix
            length_bytes = sock.recv(4)
            if not length_bytes or len(length_bytes) != 4:
                return None
            
            length = int.from_bytes(length_bytes, 'big')
            
            # Receive full message
            data = b''
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    return None
                data += chunk
            
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"[!] Protocol error: {e}")
            return None

    @staticmethod
    def create_hello(cert_pem: str, nonce: str) -> dict:
        """Create hello message"""
        return {
            "type": "hello",
            "client_cert": cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def create_server_hello(cert_pem: str, nonce: str) -> dict:
        """Create server hello message"""
        return {
            "type": "server_hello",
            "server_cert": cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def create_dh_client(g: int, p: int, A: int) -> dict:
        """Create DH client message"""
        return {
            "type": "dh_client",
            "g": g,
            "p": p,
            "A": A
        }
    
    @staticmethod
    def create_dh_server(B: int) -> dict:
        """Create DH server message"""
        return {
            "type": "dh_server",
            "B": B
        }
    
    @staticmethod
    def create_encrypted_message(seqno: int, ts: int, ct: str, sig: str) -> dict:
        """Create encrypted chat message"""
        return {
            "type": "msg",
            "seqno": seqno,
            "ts": ts,
            "ct": ct,
            "sig": sig
        }
    
    @staticmethod
    def create_receipt(peer: str, first_seq: int, last_seq: int, 
                       transcript_hash: str, sig: str) -> dict:
        """Create session receipt"""
        return {
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": sig
        }