# 🔐 Secure Chat System

A console-based secure chat application implementing cryptographic primitives to achieve **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)** without relying on TLS/SSL.

[![GitHub Repository](https://img.shields.io/badge/GitHub-securechat--skeleton-blue?style=flat&logo=github)](https://github.com/emaanfatima118/securechat-skeleton.git)

## 📋 Project Information

**Course:** Information Security  
**Assignment:** #02  
**Student:** Emaan Fatima (22i-0869)  
**Repository:** https://github.com/emaanfatima118/securechat-skeleton.git

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Prerequisites](#-prerequisites)
- [Installation & Setup](#-installation--setup)
- [Configuration](#-configuration)
- [Execution Steps](#-execution-steps)
- [Sample Input/Output](#-sample-inputoutput)
- [Security Architecture](#-security-architecture)
- [Testing & Validation](#-testing--validation)
- [Project Structure](#-project-structure)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

This project demonstrates a custom application-layer security protocol with end-to-end encryption, mutual authentication, and comprehensive security features. The system implements its own PKI infrastructure and cryptographic protocols from scratch.

---

## ✨ Key Features

- **🏛️ Custom PKI Infrastructure** - Self-built Certificate Authority
- **🔑 Mutual Authentication** - X.509 certificate-based verification
- **🔒 Encrypted Communication** - AES-128 CBC with PKCS#7 padding
- **🤝 Key Agreement** - Diffie-Hellman key exchange
- **✍️ Message Integrity** - RSA-2048 digital signatures
- **🛡️ Replay Protection** - Sequence number enforcement
- **📜 Non-Repudiation** - Signed session transcripts
- **🔐 Secure Credentials** - Salted SHA-256 password hashing

---

## 📦 Prerequisites

### System Requirements
- Python 3.7 or higher
- pip (Python package manager)
- Operating System: Windows, Linux, or macOS

### Required Python Libraries
```bash
cryptography>=3.4.8
```

---

## 🚀 Installation & Setup

### Step 1: Clone the Repository
```bash
git clone https://github.com/emaanfatima118/securechat-skeleton.git
cd securechat-skeleton
```

### Step 2: Install Dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install cryptography
```

### Step 3: Verify Installation
```bash
python --version  # Should be Python 3.7+
pip list | grep cryptography  # Verify cryptography library is installed
```

---

## ⚙️ Configuration

The system uses a self-built PKI. Certificates should be generated before first run:

**Directory Structure Required:**
```
securechat-skeleton/
├── ca/
│   ├── ca_cert.pem          # CA certificate
│   └── ca_key.pem           # CA private key
├── certs/
│   ├── server_cert.pem      # Server certificate
│   ├── server_key.pem       # Server private key
│   ├── client_cert.pem      # Client certificate
│   └── client_key.pem       # Client private key
```

---

## 🎮 Execution Steps

### Method 1: Running on Same Machine (Local Testing)

#### Step 1: Start the Server
Open a terminal/command prompt:
```bash
cd securechat-skeleton
python server.py
```

**Expected Output:**
```
[SERVER] Starting Secure Chat Server...
[SERVER] Loading certificates...
[SERVER] Server listening on 127.0.0.1:5000
[SERVER] Waiting for client connection...
```

#### Step 2: Start the Client
Open a **new** terminal/command prompt:
```bash
cd securechat-skeleton
python client.py
```

**Expected Output:**
```
[CLIENT] Connecting to server at 127.0.0.1:5000...
[CLIENT] Loading certificates...
[CLIENT] Connection established!
[CLIENT] Starting mutual authentication...
```

#### Step 3: Register or Login

**First Time User - Registration:**
```
Choose option:
1. Register
2. Login
> 1

Enter username: alice
Enter password: ********
[CLIENT] Registration successful!
```

**Existing User - Login:**
```
Choose option:
1. Register
2. Login
> 2

Enter username: alice
Enter password: ********
[CLIENT] Authentication successful!
[CLIENT] Performing Diffie-Hellman key exchange...
[CLIENT] Secure channel established!
```

#### Step 4: Send Messages

**Client Side:**
```
You: Hello, this is a secure message!
[Sent at 2025-11-17 10:30:45]

Server: Message received securely!
[Received at 2025-11-17 10:30:47]

You: Testing encryption
[Sent at 2025-11-17 10:30:50]
```

#### Step 5: Exit Gracefully
```
You: /quit
[CLIENT] Generating session transcript...
[CLIENT] Signing transcript...
[CLIENT] Transcript saved to: transcripts/session_20251117_103045.txt
[CLIENT] Receipt saved to: transcripts/receipt_20251117_103045.sig
[CLIENT] Connection closed.
```

### Method 2: Running on Different Machines (Network Testing)

#### On Server Machine:
```bash
# Find your IP address
# Linux/Mac: ifconfig
# Windows: ipconfig

# Edit server.py
HOST = '0.0.0.0'  # Listen on all interfaces

# Run server
python server.py
```

#### On Client Machine:
```bash
# Edit client.py
SERVER_HOST = '192.168.1.100'  # Replace with server's IP

# Run client
python client.py
```

---

## 📋 Sample Input/Output

### Complete Session Example

#### Server Console Output:
```
[SERVER] Starting Secure Chat Server...
[SERVER] Loading CA certificate from: ca/ca_cert.pem
[SERVER] Loading server certificate from: certs/server_cert.pem
[SERVER] Server listening on 127.0.0.1:5000
[SERVER] Waiting for client connection...

[SERVER] Client connected from 127.0.0.1:54321
[SERVER] Starting mutual authentication...
[SERVER] Received client certificate
[SERVER] Verifying client certificate...
[SERVER] ✓ Certificate signature valid
[SERVER] ✓ Certificate not expired
[SERVER] ✓ Certificate CN: client
[SERVER] Sending server certificate...
[SERVER] Client authenticated successfully!

[SERVER] Performing Diffie-Hellman key exchange...
[SERVER] DH Parameters: g=2, p=FFFFFFFFFFFFF...
[SERVER] Generated private key: b
[SERVER] Computed public key: B = g^b mod p
[SERVER] Received client public key: A
[SERVER] Computed shared secret: K_s
[SERVER] Derived session key: K = SHA256(K_s)[0:16]
[SERVER] ✓ Secure channel established!

[SERVER] Waiting for login/registration...
[SERVER] Registration request received
[SERVER] Username: alice
[SERVER] Hashing password with salt...
[SERVER] User registered successfully!

Client (alice): Hello, this is a secure message!
[Received at 2025-11-17 10:30:45 | Seq: 1]
[SERVER] ✓ Signature verified
[SERVER] ✓ Sequence number valid
[SERVER] ✓ Timestamp valid

You: Message received securely!
[Sent at 2025-11-17 10:30:47 | Seq: 1]

Client (alice): Testing encryption
[Received at 2025-11-17 10:30:50 | Seq: 2]

[SERVER] Client initiated disconnect
[SERVER] Generating session transcript...
[SERVER] Computing transcript hash...
[SERVER] Signing transcript with server private key...
[SERVER] Exchanging receipts with client...
[SERVER] ✓ Client receipt verified
[SERVER] Session closed. Transcript saved to: transcripts/server_session_20251117_103045.txt
```

#### Client Console Output:
```
[CLIENT] Connecting to server at 127.0.0.1:5000...
[CLIENT] Loading CA certificate from: ca/ca_cert.pem
[CLIENT] Loading client certificate from: certs/client_cert.pem
[CLIENT] Connection established!

[CLIENT] Starting mutual authentication...
[CLIENT] Sending client certificate...
[CLIENT] Received server certificate
[CLIENT] Verifying server certificate...
[CLIENT] ✓ Certificate signature valid
[CLIENT] ✓ Certificate not expired
[CLIENT] ✓ Certificate CN: server
[CLIENT] Server authenticated successfully!

[CLIENT] Performing Diffie-Hellman key exchange...
[CLIENT] Generated private key: a
[CLIENT] Computed public key: A = g^a mod p
[CLIENT] Sending DH parameters: g, p, A
[CLIENT] Received server public key: B
[CLIENT] Computed shared secret: K_s
[CLIENT] Derived session key: K = SHA256(K_s)[0:16]
[CLIENT] ✓ Secure channel established!

Choose option:
1. Register
2. Login
> 1

Enter username: alice
Enter password: ********
[CLIENT] Sending encrypted credentials...
[CLIENT] Registration successful!

--- Secure Chat Session Started ---
Type '/quit' to exit

You: Hello, this is a secure message!
[CLIENT] Encrypting message with AES-128-CBC...
[CLIENT] Computing message hash...
[CLIENT] Signing hash with private key...
[Sent at 2025-11-17 10:30:45 | Seq: 1]

Server: Message received securely!
[Received at 2025-11-17 10:30:47 | Seq: 1]
[CLIENT] ✓ Signature verified
[CLIENT] ✓ Sequence number valid
[CLIENT] Message decrypted successfully

You: Testing encryption
[Sent at 2025-11-17 10:30:50 | Seq: 2]

You: /quit
[CLIENT] Initiating graceful shutdown...
[CLIENT] Generating session transcript...
Transcript contains:
  - 2 messages sent
  - 1 message received
  - Session duration: 5 seconds

[CLIENT] Computing transcript hash: 8f7a3bc4e2d1...
[CLIENT] Signing transcript with client private key...
[CLIENT] Exchanging receipts with server...
[CLIENT] ✓ Server receipt verified

Session artifacts saved:
  📄 Transcript: transcripts/session_20251117_103045.txt
  ✍️  Receipt: transcripts/receipt_20251117_103045.sig

[CLIENT] Connection closed.
```

### Sample Transcript File Format

**File: `transcripts/session_20251117_103045.txt`**
```
=== SECURE CHAT SESSION TRANSCRIPT ===
Session ID: 20251117_103045
Start Time: 2025-11-17 10:30:45
End Time: 2025-11-17 10:30:55
Duration: 10 seconds

Participants:
  - Client: alice (CN=client)
  - Server: server (CN=server)

Security Parameters:
  - Key Exchange: Diffie-Hellman (2048-bit)
  - Encryption: AES-128-CBC
  - Signature: RSA-2048-SHA256
  - Session Key: 8a7f4e2d1c9b...

Messages:
[2025-11-17 10:30:45] alice: Hello, this is a secure message!
  Seq: 1 | Signature: 3f8a9c7e... | Status: Verified

[2025-11-17 10:30:47] server: Message received securely!
  Seq: 1 | Signature: 2d7b8f4a... | Status: Verified

[2025-11-17 10:30:50] alice: Testing encryption
  Seq: 2 | Signature: 9e4f7c2a... | Status: Verified

Transcript Hash (SHA-256): 8f7a3bc4e2d1a6f9...
Signature: [Signed by client private key]

=== END OF TRANSCRIPT ===
```

### Sample Receipt File Format

**File: `transcripts/receipt_20251117_103045.sig`**
```
-----BEGIN SIGNATURE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx7fJ8k2mQ9pR7vL3
wN4t8xY6zK1mP9sQ4jF8dL2eR5wH3nM7kP9vQ2xT6yF8sL4jN9rM3wP7qK5t
[... Base64 encoded signature ...]
8dF6gK3hN9xM2pL7vQ4wR5yK8fT2nJ3sP9qL7vN4wM8xY6zK1mP9sQ4jF8dL
-----END SIGNATURE-----

Transcript Hash: 8f7a3bc4e2d1a6f9...
Signed By: client (alice)
Timestamp: 2025-11-17 10:30:55
```

---

## 🏗️ Security Architecture

### Four-Phase Protocol

#### **PHASE 1: CONTROL PLANE** (Certificate & Authentication)
```
Client                                  Server
  |                                        |
  |------ Certificate + Nonce ----------->|
  |                                        | Verify cert
  |<----- Certificate + Nonce ------------|
  | Verify cert                            |
  |                                        |
  |<===== Temp DH Exchange for Control ===|
  |                                        |
  |------ Encrypted Credentials --------->|
  |                                        | Register/Login
  |<----- Auth Success/Failure -----------|
```

#### **PHASE 2: KEY AGREEMENT** (Diffie-Hellman)
```
Client                                  Server
  |                                        |
  | a = random()                           | b = random()
  | A = g^a mod p                          | B = g^b mod p
  |                                        |
  |------- g, p, A -------------------->|
  |<---------- B --------------------------|
  |                                        |
  | K_s = B^a mod p                        | K_s = A^b mod p
  | K = SHA256(K_s)[0:16]                  | K = SHA256(K_s)[0:16]
```

#### **PHASE 3: DATA PLANE** (Encrypted Messaging)
```
For each message:
1. CT = AES-128-CBC(plaintext, K)
2. h = SHA256(seq || timestamp || CT)
3. sig = RSA-Sign(h, private_key)
4. Send: {seq, timestamp, CT, sig}
5. Verify signature & sequence
6. Decrypt & display
```

#### **PHASE 4: TEARDOWN** (Non-Repudiation)
```
Client                                  Server
  |                                        |
  | transcript_hash = SHA256(messages)     | transcript_hash = SHA256(messages)
  | receipt = RSA-Sign(hash, client_key)   | receipt = RSA-Sign(hash, server_key)
  |                                        |
  |<====== Exchange Receipts ============>|
  |                                        |
  | Verify server receipt                  | Verify client receipt
  | Save transcript + receipt              | Save transcript + receipt
```

---

## 🧪 Testing & Validation

### Test 1: Wireshark - Encrypted Payloads
**Objective:** Verify all communication is encrypted

**Steps:**
1. Start Wireshark and capture on loopback interface
2. Run server and client
3. Send messages
4. Stop capture and search for plaintext strings

**Expected Result:** ✓ No plaintext "hello", "password", or message content visible

### Test 2: Invalid Certificate Tests

**Part A - Self-Signed Certificate:**
```bash
# Replace client certificate with self-signed one
openssl req -x509 -newkey rsa:2048 -keyout fake_key.pem -out fake_cert.pem -days 365 -nodes
cp fake_cert.pem certs/client_cert.pem
python client.py
```
**Expected Result:** ✓ Connection rejected - "Certificate not signed by trusted CA"

**Part B - Expired Certificate:**
```bash
# Create expired certificate (valid for -1 days)
openssl req -x509 -newkey rsa:2048 -keyout expired_key.pem -out expired_cert.pem -days -1 -nodes
cp expired_cert.pem certs/client_cert.pem
python client.py
```
**Expected Result:** ✓ Connection rejected - "Certificate expired"

### Test 3: Message Tampering Detection
**Steps:**
1. Modify `client.py` to flip bits in ciphertext before sending
2. Send a message

**Expected Result:** ✓ Server rejects message - "Signature verification failed"

### Test 4: Replay Attack Prevention
**Steps:**
1. Capture a valid encrypted message packet
2. Resend the same packet

**Expected Result:** ✓ Server rejects - "Invalid sequence number"

### Test 5: Non-Repudiation Verification
**Steps:**
1. Complete a chat session
2. Verify receipt file with transcript

```bash
python verify_receipt.py transcripts/session_20251117_103045.txt transcripts/receipt_20251117_103045.sig
```
**Expected Result:** ✓ "Signature valid - Transcript verified"

**Tamper test:**
```bash
# Modify transcript file
echo "Fake message" >> transcripts/session_20251117_103045.txt
python verify_receipt.py transcripts/session_20251117_103045.txt transcripts/receipt_20251117_103045.sig
```
**Expected Result:** ✓ "Signature invalid - Transcript has been tampered"

---

## 📁 Project Structure

```
securechat-skeleton/
├── server.py                   # Server application
├── client.py                   # Client application
├── setup_pki.py               # PKI setup script
├── verify_receipt.py          # Receipt verification utility
├── requirements.txt           # Python dependencies
├── README.md                  # This file
│
├── ca/                        # Certificate Authority
│   ├── ca_cert.pem           # CA certificate
│   └── ca_key.pem            # CA private key
│
├── certs/                     # Client/Server certificates
│   ├── server_cert.pem       # Server certificate
│   ├── server_key.pem        # Server private key
│   ├── client_cert.pem       # Client certificate
│   └── client_key.pem        # Client private key
│
├── credentials/               # User database
│   └── users.db              # Salted password hashes
│
├── transcripts/               # Session records
│   ├── session_*.txt         # Chat transcripts
│   └── receipt_*.sig         # Signed receipts
│
└── logs/                      # Application logs
    ├── server.log
    └── client.log
```

---

## 🔧 Troubleshooting

```bash
pip install --upgrade pip
pip install cryptography
```

---

## 🔒 Security Properties

| Property | Implementation | Status |
|----------|---------------|--------|
| Confidentiality | AES-128-CBC | ✅ |
| Integrity | SHA-256 + RSA signatures | ✅ |
| Authenticity | X.509 certificates | ✅ |
| Non-Repudiation | Signed receipts | ✅ |
| Forward Secrecy | Ephemeral DH keys | ✅ |
| Replay Protection | Sequence numbers | ✅ |

---

## 👨‍💻 Author

**Emaan Fatima**  
Roll Number: 22i-0869  
Course: Information Security  
GitHub: [@emaanfatima118](https://github.com/emaanfatima118)

---

## 🔗 Links

- **GitHub Repository:** https://github.com/emaanfatima118/securechat-skeleton.git
- **Project Report:** [View Report](docs/i220869-EmaanFatima-Report-A02.docx)
- **Test Report:** [View Tests](docs/i220869-EmaanFatima-TestReport-A02.docx)

---
