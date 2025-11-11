"""Create Root CA (RSA + self-signed X.509) using cryptography."""

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509 import NameOID, CertificateBuilder, random_serial_number
from cryptography.x509 import BasicConstraints
from datetime import datetime, timedelta
import cryptography.x509 as x509


CERTS_ROOT_PATH = "../certs"

# 1. Generate RSA private key for Root CA
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# 2. Build subject and issuer (Root CA is self-signed, so they are the same)
subject = issuer = x509.Name(
    [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "pk"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST NUCES"),
        x509.NameAttribute(NameOID.COMMON_NAME, "My Root CA"),
    ]
)

# 3. Create self-signed certificate
root_cert = (
    CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(public_key)
    .serial_number(random_serial_number())
    .not_valid_before(datetime.now())
    .not_valid_after(datetime.now() + timedelta(days=1))  # valid for 1 day
    .add_extension(
        BasicConstraints(ca=True, path_length=None),
        critical=True,
    )
    .sign(private_key, hashes.SHA256())
)

# 4. Serialize private key to PEM
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

# 5. Serialize certificate to PEM
cert_pem = root_cert.public_bytes(serialization.Encoding.PEM)

# 6. Save to files (optional)
with open(f"{CERTS_ROOT_PATH}/rootCA.key", "wb") as f:
    f.write(private_pem)

with open(f"{CERTS_ROOT_PATH}rootCA.crt", "wb") as f:
    f.write(cert_pem)

print("Root CA private key and certificate generated successfully!")
