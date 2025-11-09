"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""

import socket
import json
from typing import Optional
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import (
    Name,
    NameAttribute,
    NameOID,
    CertificateBuilder,
    BasicConstraints,
    KeyUsage,
    ExtendedKeyUsage,
    ExtendedKeyUsageOID,
    random_serial_number,
)
from datetime import datetime, timedelta
from cryptography import x509

# ------------------- Socket Server -------------------
CA_HOST = "0.0.0.0"
CA_PORT = 8000


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
                key_encipherment=is_server,
                content_commitment=not is_server,
                data_encipherment=is_server,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    eku = ExtendedKeyUsage(
        [
            ExtendedKeyUsageOID.SERVER_AUTH
            if is_server
            else ExtendedKeyUsageOID.CLIENT_AUTH
        ]
    )
    cert_builder = cert_builder.add_extension(eku, critical=False)

    certificate = cert_builder.sign(
        private_key=ca_private_key, algorithm=hashes.SHA256()
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    return certificate_pem


def start_ca_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((CA_HOST, CA_PORT))
        s.listen(5)
        print(f"CA server listening on {CA_HOST}:{CA_PORT}")

        while True:
            conn, addr = s.accept()
            with conn:
                print(f"Connected by {addr}")
                data = b""

                data = conn.recv(4096)

                # Decode JSON request
                try:
                    request = json.loads(data.decode())
                    subject_public_key_pem = request["public_key"].encode()
                    subject_common_name = request.get("common_name", "Unknown")
                    subject_email = request.get("email")
                    country = request.get("country")
                    state = request.get("state")
                    locality = request.get("locality")
                    organization = request.get("organization")
                    is_server = request.get("is_server", True)
                    validity_days = request.get("validity_days", 1)

                    # Issue certificate
                    cert_pem = issue_certificate(
                        ca_key_path="rootCA.key",
                        ca_cert_path="rootCA.crt",
                        subject_public_key_pem=subject_public_key_pem,
                        subject_common_name=subject_common_name,
                        subject_email=subject_email,
                        country=country,
                        state=state,
                        locality=locality,
                        organization=organization,
                        is_server=is_server,
                        validity_days=validity_days,
                    )

                    # Send back certificate
                    conn.sendall(cert_pem)
                    print(f"Certificate issued for {subject_common_name}")
                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    conn.sendall(error_msg.encode())


# ------------------- Run Server -------------------
if __name__ == "__main__":
    start_ca_server()
