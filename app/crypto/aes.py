"""AES-128(ECB)+PKCS#7 helpers (use library).""" 

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

def generate_aes_key() -> bytes:
    """Generate a random 16-byte AES key."""
    return os.urandom(16)

def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt plaintext using AES-128 in ECB mode with PKCS#7 padding."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext using AES-128 in ECB mode with PKCS#7 padding."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


# # Example usage:
# if __name__ == "__main__":
#     key = generate_aes_key()
#     message = b"Hello, World!"
#     ciphertext = aes_encrypt(key, message)
#     decrypted_message = aes_decrypt(key, ciphertext)

#     print(f"Original Message: {message}")
#     print(f"Ciphertext: {ciphertext}")
#     print(f"Decrypted Message: {decrypted_message}")
#     print(f"Key: {key}")