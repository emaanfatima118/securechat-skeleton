#!/usr/bin/env python3
"""
gen_cert.py - Generate Server and Client Certificates
Issues X.509 certificates signed by the root CA
"""

import os
import sys
import datetime
import ipaddress

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

def load_ca():
    """Load the CA certificate and private key"""
    ca_key_path = "certs/ca_key.pem"
    ca_cert_path = "certs/ca_cert.pem"
    
    if not os.path.exists(ca_key_path) or not os.path.exists(ca_cert_path):
        print("[!] Error: CA certificate not found. Run gen_ca.py first!")
        sys.exit(1)
    
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_key, ca_cert

def generate_certificate(entity_type: str, common_name: str):
    """
    Generate a certificate for server or client
    
    Args:
        entity_type: 'server' or 'client'
        common_name: CN for the certificate
    """
    print(f"\n{'='*60}")
    print(f"GENERATING {entity_type.upper()} CERTIFICATE")
    print("="*60)
    
    # Load CA
    print("[*] Loading CA...")
    ca_key, ca_cert = load_ca()
    print("[+] CA loaded")
    
    # Generate private key for entity
    print(f"[*] Generating RSA-2048 private key for {entity_type}...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    print("[+] Private key generated")
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST-NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"SecureChat {entity_type.capitalize()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print("[*] Building certificate...")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
    )
    
    # Add appropriate key usage based on entity type
    if entity_type == "server":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        # Add Subject Alternative Name for server
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(common_name),
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
    
    # Sign the certificate with CA key
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    print("[+] Certificate signed by CA")
    
    # Write private key
    key_filename = f"certs/{entity_type}_key.pem"
    with open(key_filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] Private key saved: {key_filename}")
    
    # Write certificate
    cert_filename = f"certs/{entity_type}_cert.pem"
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] Certificate saved: {cert_filename}")
    
    # Display certificate info
    print(f"\nSubject     : {cert.subject.rfc4514_string()}")
    print(f"Issuer      : {cert.issuer.rfc4514_string()}")
    print(f"Serial      : {cert.serial_number}")
    print(f"Valid From  : {cert.not_valid_before}")
    print(f"Valid Until : {cert.not_valid_after}")

def main():
    """Main function"""
    print("="*60)
    print("CERTIFICATE GENERATION FOR SECURE CHAT")
    print("="*60)
    
    # Generate server certificate
    generate_certificate("server", "localhost")
    
    # Generate client certificate
    generate_certificate("client", "securechat-client")
    
    print("\n" + "="*60)
    print("[+] All certificates generated successfully!")
    print("[!] IMPORTANT: Keep all *_key.pem files secure!")
    print("[!] NEVER commit them to GitHub!")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()