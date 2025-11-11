"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import os
from typing import Optional
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.x509 import (
    Name,
    NameAttribute,
    CertificateBuilder,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    SubjectAlternativeName,
    DNSName,
    random_serial_number,
)

CERTS_ROOT_PATH = "../certs"


# ------------------- Certificate Issuer -------------------
def issue_certificate(
    ca_key_path: str,
    ca_cert_path: str,
    subject_public_key_pem: bytes,
    subject_common_name: str,
    subject_email: Optional[str] = None,
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None,
    organization: Optional[str] = None,
    is_server: bool = True,
    validity_days: int = 1,
):
    """Issue a certificate for a client or server signed by CA."""

    # Load CA private key
    with open(ca_key_path, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(f.read(), password=None)

    # Load CA certificate
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # Load subject public key
    subject_public_key = serialization.load_pem_public_key(subject_public_key_pem)

    # Build subject DN
    dn_attributes = []
    if country:
        dn_attributes.append(NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        dn_attributes.append(NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        dn_attributes.append(NameAttribute(NameOID.LOCALITY_NAME, locality))
    if organization:
        dn_attributes.append(NameAttribute(NameOID.ORGANIZATION_NAME, organization))
    dn_attributes.append(NameAttribute(NameOID.COMMON_NAME, subject_common_name))
    if subject_email:
        dn_attributes.append(NameAttribute(NameOID.EMAIL_ADDRESS, subject_email))

    subject_name = Name(dn_attributes)

    # Build certificate
    cert_builder = (
        CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(ca_cert.subject)
        .public_key(subject_public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    # Extended Key Usage
    eku = ExtendedKeyUsage(
        [ExtendedKeyUsageOID.SERVER_AUTH if is_server else ExtendedKeyUsageOID.CLIENT_AUTH]
    )
    cert_builder = cert_builder.add_extension(eku, critical=False)

    # Subject Alternative Name (SAN)
    cert_builder = cert_builder.add_extension(
        SubjectAlternativeName([DNSName(subject_common_name)]), critical=False
    )

    # Sign the certificate
    certificate = cert_builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    return certificate_pem


# ------------------- Key Management -------------------
def save_key(public_key, private_key, party: str):
    """
    Save RSA key pair for a given party (client/server).
    """
    assert party in ("client", "server")

    os.makedirs(CERTS_ROOT_PATH, exist_ok=True)

    # Save private key
    with open(f"{CERTS_ROOT_PATH}/{party}_private_key.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    b"my_secure_password"
                ),
            )
        )

    # Save public key
    with open(f"{CERTS_ROOT_PATH}/{party}_public_key.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


def generate_key_pair():
    """Generate an RSA private/public key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_key, public_key, public_pem


# ------------------- Certificate Generation -------------------
def generate_and_save_certificate_server(public_key_pem):
    """Generate and save the server certificate."""

    cert_pem = issue_certificate(
        ca_key_path=f"{CERTS_ROOT_PATH}/rootCA.key",
        ca_cert_path=f"{CERTS_ROOT_PATH}/rootCA.crt",
        subject_public_key_pem=public_key_pem,
        subject_common_name="server",
        subject_email="server@gmail.com",
        country="PK",
        organization="FAST",
        is_server=True,
        validity_days=1,
    )

    with open(f"{CERTS_ROOT_PATH}/server_cert.crt", "wb") as f:
        f.write(cert_pem)


def generate_and_save_certificate_client(public_key_pem):
    """Generate and save the client certificate."""

    cert_pem = issue_certificate(
        ca_key_path=f"{CERTS_ROOT_PATH}/rootCA.key",
        ca_cert_path=f"{CERTS_ROOT_PATH}/rootCA.crt",
        subject_public_key_pem=public_key_pem,
        subject_common_name="client",
        subject_email="client@gmail.com",
        country="PK",
        organization="FAST",
        is_server=False,
        validity_days=1,
    )

    with open(f"{CERTS_ROOT_PATH}/client_cert.crt", "wb") as f:
        f.write(cert_pem)


# ------------------- Execute -------------------
def execute():
    client_priv, client_pub, client_pub_pem = generate_key_pair()
    server_priv, server_pub, server_pub_pem = generate_key_pair()

    save_key(client_pub, client_priv, "client")
    save_key(server_pub, server_priv, "server")

    generate_and_save_certificate_client(public_key_pem=client_pub_pem)
    generate_and_save_certificate_server(public_key_pem=server_pub_pem)


if __name__ == "__main__":
    execute()
