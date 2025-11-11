"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from datetime import datetime, timezone

def verify_certificate(cert_pem: bytes, ca_cert_pem: bytes) -> bool:
    try:
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_pub = ca_cert.public_key()
        # Only RSA public keys support verify for X.509 certs in this context
        if isinstance(ca_pub, rsa.RSAPublicKey):
            # If signature_hash_algorithm is None, use SHA256 as fallback
            hash_algo = cert.signature_hash_algorithm
            if hash_algo is None:
                from cryptography.hazmat.primitives import hashes
                hash_algo = hashes.SHA256()
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algo
            )
        else:
            return False
        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            return False
        if cert.issuer != ca_cert.subject:
            return False
        return True
    except Exception:
        return False
