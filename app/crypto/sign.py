"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""

import base64, time, hashlib, json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.aes import aes_encrypt, aes_decrypt


def sign_digest(private_key, digest: bytes) -> bytes:
    """Sign SHA-256 digest using RSA PKCS#1 v1.5."""
    return private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())


def verify_signature(public_key, digest: bytes, signature: bytes) -> bool:
    """Verify RSA signature against SHA-256 digest."""
    try:
        public_key.verify(signature, digest, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def make_data_message(
    seqno: int, plaintext: str, session_key: bytes, private_key
) -> dict:
    """Construct signed + encrypted data-plane message."""
    ts = int(time.time() * 1000)
    ct_bytes = aes_encrypt(session_key, plaintext.encode())
    ct_b64 = base64.b64encode(ct_bytes).decode()

    digest = hashlib.sha256(f"{seqno}{ts}{ct_b64}".encode()).digest()
    sig = sign_digest(private_key, digest)
    sig_b64 = base64.b64encode(sig).decode()

    return {
        "type": "msg",
        "seqno": seqno,
        "ts": ts,
        "ct": ct_b64,
        "sig": sig_b64,
    }


def parse_data_message(msg: dict, session_key: bytes, sender_pubkey, last_seqno: int):
    """Verify signature, freshness, and decrypt AES ciphertext."""
    seqno = msg["seqno"]
    ts = msg["ts"]
    ct_b64 = msg["ct"]
    sig_b64 = msg["sig"]

    ct_bytes = base64.b64decode(ct_b64)
    sig_bytes = base64.b64decode(sig_b64)

    digest = hashlib.sha256(f"{seqno}{ts}{ct_b64}".encode()).digest()

    if not verify_signature(sender_pubkey, digest, sig_bytes):
        raise ValueError("Invalid signature")
    if seqno <= last_seqno:
        raise ValueError("Replay detected")

    plaintext = aes_decrypt(session_key, ct_bytes).decode()
    return plaintext, seqno
