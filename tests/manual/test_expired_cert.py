#!/usr/bin/env python3
"""Generate an expired certificate"""

import sys
import os
sys.path.insert(0, os.path.abspath('.'))

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

# Load CA
with open("certs/ca_key.pem", "rb") as f:
    ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

with open("certs/ca_cert.pem", "rb") as f:
    ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

# Generate client key
private_key = rsa.generate_private_key(65537, 2048, default_backend())

# Create EXPIRED cert (expired yesterday)
subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"securechat-client"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(ca_cert.subject)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=365))
    .not_valid_after(datetime.datetime.utcnow() - datetime.timedelta(days=1))  # EXPIRED!
    .sign(ca_key, hashes.SHA256(), default_backend())
)

# Save
with open("certs/client_cert_expired.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open("certs/client_key_expired.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("[+] Expired certificate created")