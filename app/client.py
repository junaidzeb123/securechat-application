# client.py
import socket
import json
import os
import secrets
from typing import Any, Dict
import base64
from common.protocol import (
    HelloMessage,
    DH_P_Q_Client,
    DH_Server_B,
    LoginMessage,
    RegisterMessage,
    SecureMessage,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import aead
from cryptography import x509
import hashlib
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from crypto.aes import aes_encrypt
from crypto.dh import (
    dh_generate_parameters,
    dh_generate_private_key,
    dh_derive_shared_key,
)

HOST = "127.0.0.1"
PORT = 9000
CLIENT_PRIVATE_KEY = "../certs/client_private_key.pem"
CLIENT_PUBLIC_KEY = "../certs/client_public_key.pem"
CLIENT_CERT = "../certs/client_cert.crt"
CA_CERT = "../certs/rootCA.crt"


def send_msg(sock: socket.socket, obj: Any):
    data = json.dumps(obj.__dict__).encode()
    length = len(data).to_bytes(4, "big")
    sock.sendall(length + data)


def recv_msg(sock: socket.socket) -> Any:
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    length = int.from_bytes(raw_len, "big")
    chunks = b""
    while len(chunks) < length:
        chunk = sock.recv(length - len(chunks))
        if not chunk:
            raise ConnectionError("Socket closed")
        chunks += chunk
    return json.loads(chunks.decode())


def verify_cert_signed_by_ca(cert_pem: bytes, ca_cert: x509.Certificate) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            serialization.pkcs1v15
            if False
            else __import__(
                "cryptography"
            ).hazmat.primitives.asymmetric.padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception:
        # the above construct is awkward to avoid explicit import misuse — use a simpler verify in practice
        try:
            ca_cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                # Use padding PKCS1v15 directly:
                __import__(
                    "cryptography"
                ).hazmat.primitives.asymmetric.padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
            return True
        except Exception as e:
            print("[Client] Certificate verification error:", e)
            return False


def aes_gcm_encrypt(key: bytes, plaintext: bytes) -> Dict[str, str]:
    iv = secrets.token_bytes(12)
    aesgcm = aead.AESGCM(key)
    ct = aesgcm.encrypt(iv, plaintext, None)
    return {"iv": iv.hex(), "ct": ct.hex()}


def aes_gcm_decrypt(key: bytes, enc: Dict[str, str]) -> bytes:
    iv = bytes.fromhex(enc["iv"])
    ct = bytes.fromhex(enc["ct"])
    aesgcm = aead.AESGCM(key)
    return aesgcm.decrypt(iv, ct, None)


class Client:
    def __init__(self):
        self._load_keys_and_certificate()

    def _load_keys_and_certificate(self):
        # Load CA private key
        with open(CLIENT_PRIVATE_KEY, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )

        with open(CLIENT_PUBLIC_KEY, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

        # Load CA certificate
        with open(CLIENT_CERT, "rb") as f:
            self.client_cert = f.read()  # raw PEM bytes

        with open(CA_CERT, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def perform_dh_key_exchange_client(self, s):
        """Perform Diffie–Hellman key exchange as client."""
        # Generate DH parameters (p, g)
        parameters = dh_generate_parameters(generator=5, key_size=512)

        # Generate client key pair
        client_priv = dh_generate_private_key(parameters)
        client_pub = client_priv.public_key()

        # Extract p, g, and A = g^a mod p
        pn = parameters.parameter_numbers()
        p, g = pn.p, pn.g
        A = client_pub.public_numbers().y

        # Send DH parameters and public key A to server
        dh_msg = DH_P_Q_Client(type="dh_client", p=str(p), g=str(g), A=str(A))
        send_msg(s, dh_msg)

        # Receive server's public key B
        dh_msg_server = DH_Server_B(**recv_msg(s))
        if dh_msg_server.type != "dh_server":
            print("[Client] Expected dh_server")
            return None

        # Reconstruct server's public key
        server_pub_numbers = dh.DHPublicNumbers(
            int(dh_msg_server.B), dh.DHParameterNumbers(p, g)
        )
        server_pub_key = server_pub_numbers.public_key()

        # Derive shared session key
        session_key = dh_derive_shared_key(client_priv, server_pub_key)

        print("[Client] Session key established:", session_key.hex())
        return session_key

    def start(self):
        # connect server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # send hello: cert + nonce
        nonce = secrets.token_bytes(16)
        hello = HelloMessage(
            type="hello", cert=self.client_cert.decode(), nonce=nonce.hex()
        )

        send_msg(s, hello)

        # receive server hello
        server_hello = recv_msg(s)
        server_cert_pem = server_hello["cert"].encode()
        server_nonce = bytes.fromhex(server_hello["nonce"])

        # verify server cert
        server_cert_obj = x509.load_pem_x509_certificate(server_cert_pem)
        try:
            self.ca_cert.public_key().verify(
                server_cert_obj.signature,
                server_cert_obj.tbs_certificate_bytes,
                PKCS1v15(),
                server_cert_obj.signature_hash_algorithm,
            )
            print("[Client] Server certificate verified.")
        except Exception as e:
            print("[Client] Server certificate verification failed:", e)
            s.close()
            return

        
        session_key = self.perform_dh_key_exchange_client(s)
        print("[Client] Session key established.", session_key.hex())

        # interaction loop: register/login
        print("\n1) Register\n2) Login\n3) Quit")
        choice = input("Choice: ").strip()
        if choice == "1":
            username = input("username: ").strip()
            password = input("password: ").strip()
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            payload = {
                "type": "register",
                "username": username,
                "password": password,
                "password_hash": pw_hash,
            }
            register_msg = RegisterMessage(payload=payload)
            enc = aes_encrypt(session_key, json.dumps(register_msg.__dict__).encode())
            enc_b64 = base64.b64encode(enc).decode()  # bytes → base64 string
            enc_msg = SecureMessage(payload=enc_b64)
            print("[Client] Sending register message:", enc)
            send_msg(s, enc_msg)
        elif choice == "2":
            username = input("username: ").strip()
            password = input("password: ").strip()
            pw_hash = hashlib.sha256(password.encode()).hexdigest()
            payload = {
                "type": "login",
                "username": username,
                "password": password,
                "password_hash": pw_hash,
            }
            register_msg = LoginMessage(payload=payload)
            enc = aes_encrypt(session_key, json.dumps(register_msg.__dict__).encode())
            enc_b64 = base64.b64encode(enc).decode()  # bytes → base64 string
            enc_msg = SecureMessage(payload=enc_b64)
            print("[Client] Sending register message:", enc)
            send_msg(s, enc_msg)
        while True:
            pass
        s.close()


if __name__ == "__main__":
    if not os.path.exists(CA_CERT):
        print("rootCA.crt not found. Start ca.py first.")
        exit(1)
    client = Client()
    client.start()
