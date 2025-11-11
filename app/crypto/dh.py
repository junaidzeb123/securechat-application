"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 

from cryptography.hazmat.primitives.asymmetric import dh
import hashlib

def dh_generate_parameters(generator: int = 2, key_size: int = 2048) -> dh.DHParameters:
    return dh.generate_parameters(generator=generator, key_size=key_size)

def dh_generate_private_key(parameters: dh.DHParameters) -> dh.DHPrivateKey:
    return parameters.generate_private_key()

def dh_derive_shared_key(private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
    shared = private_key.exchange(peer_public_key)
    return hashlib.sha256(shared).digest()[:16]
