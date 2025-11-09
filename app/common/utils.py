"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""

import os
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def now_ms():
    raise NotImplementedError


def b64e(b: bytes):
    raise NotImplementedError


def b64d(s: str):
    raise NotImplementedError


def sha256_hex(data: bytes):
    raise NotImplementedError


def get_ca_cert() -> bytes:
    """
    Load and return the CA certificate from disk.

    Returns:
        bytes: The contents of the CA certificate file in PEM format.

    Raises:
        FileNotFoundError: If the CA certificate file does not exist.
        IOError: If there is an error reading the file.
    """
    root_ca_path = "../scripts/rootCA.crt"

    if not os.path.exists(root_ca_path):
        raise FileNotFoundError(f"CA certificate not found at {root_ca_path}")

    with open(root_ca_path, "rb") as f:
        ca_cert = f.read()

    return ca_cert


def verify_server_certificate(cert: bytes) -> bool:
    """
    Verify a server certificate against a CA certificate.

    Args:
        cert: PEM-encoded server certificate bytes

    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        # Load CA and server certificates
        ca_cert = get_ca_cert()
        ca_cert_obj = x509.load_pem_x509_certificate(ca_cert)
        server_cert_obj = x509.load_pem_x509_certificate(cert)

        # Get CA's public key
        ca_public_key = ca_cert_obj.public_key()

        # Verify the signature on the server certificate
        # The signature is over the TBS (To Be Signed) certificate data
        ca_public_key.verify(
            server_cert_obj.signature,
            server_cert_obj.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server_cert_obj.signature_hash_algorithm,
        )

        print("✓ Certificate signature is valid")

        # 1. Check if certificate is expired
        now = datetime.now(timezone.utc)
        if now < server_cert_obj.not_valid_before_utc:
            print("✗ Certificate not yet valid")
            return False
        if now > server_cert_obj.not_valid_after_utc:
            print("✗ Certificate has expired")
            return False

        # 2. Check if issuer matches CA subject
        if server_cert_obj.issuer != ca_cert_obj.subject:
            print("✗ Certificate issuer does not match CA subject")
            return False

        print("✓ All certificate checks passed")
        return True

    except InvalidSignature:
        print("✗ Certificate signature verification failed")
        return False
    except Exception as e:
        print(f"✗ Server certificate verification failed: {e}")
        return False
