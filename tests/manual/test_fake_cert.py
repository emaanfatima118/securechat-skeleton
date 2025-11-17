#!/usr/bin/env python3
"""Generate a self-signed certificate (not from CA)"""

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime

# Generate key
private_key = rsa.generate_private_key(65537, 2048, default_backend())

# Create self-signed cert
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"Fake Client"),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.utcnow())
    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=1))
    .sign(private_key, hashes.SHA256(), default_backend())
)

# Save
with open("certs/client_cert_fake.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

with open("certs/client_key_fake.pem", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("[+] Fake self-signed certificate created")