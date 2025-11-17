#!/usr/bin/env python3
"""
gen_ca.py - Generate Root Certificate Authority
Creates a self-signed root CA for the secure chat system
"""

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_root_ca():
    """Generate a self-signed root CA certificate and private key"""
    
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    # Generate RSA private key (2048 bits as per RSA standard)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Write private key to file
    with open("certs/ca_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Write certificate to file
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("[+] Root CA generated successfully!")
    print("[+] Private Key: certs/ca_key.pem")
    print("[+] Certificate: certs/ca_cert.pem")
    print("\n[!] IMPORTANT: Keep ca_key.pem secure and never commit it to GitHub!")
    
    # Display certificate info
    print("\n=== Certificate Information ===")
    print(f"Subject: {cert.subject.rfc4514_string()}")
    print(f"Issuer: {cert.issuer.rfc4514_string()}")
    print(f"Serial Number: {cert.serial_number}")
    print(f"Valid From: {cert.not_valid_before}")
    print(f"Valid Until: {cert.not_valid_after}")

if __name__ == "__main__":
    generate_root_ca()