# client.py
import socket
import json
import os
import secrets
import hashlib
from typing import Any, Dict
from common.protocol import HelloMessage
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import aead
from cryptography import x509

HOST = "127.0.0.1"
PORT = 9000
CLIENT_PRIVATE_KEY = "../certs/client_private_key.pem"
CLIENT_PUBLIC_KEY = "../certs/client_public_key.pem"
CLIENT_CERT = "../certs/client.crt"
CA_CERT = "../certs/rootCA.crt"


def send_msg(sock: socket.socket, obj: Any):
    data = json.dumps(obj).encode()
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
            self.client_cert = x509.load_pem_x509_certificate(f.read())

        with open(CA_CERT, "wb"):
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def start(self):
        # connect server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HOST, PORT))

        # send hello: cert + nonce
        nonce = secrets.token_bytes(16)
        hello = {
            "type": "hello",
            "cert": self.client_cert.decode(),
            "nonce": nonce.hex(),
        }
        send_msg(s, hello)

        # receive server hello
        server_hello = recv_msg(s)
        server_cert_pem = server_hello["cert"].encode()
        server_nonce = bytes.fromhex(server_hello["nonce"])
        print("[Client] Received server hello. Verifying server certificate...")

        # verify server cert
        server_cert_obj = x509.load_pem_x509_certificate(server_cert_pem)
        try:
            self.ca_cert.public_key().verify(
                server_cert_obj.signature,
                server_cert_obj.tbs_certificate_bytes,
                __import__(
                    "cryptography"
                ).hazmat.primitives.asymmetric.padding.PKCS1v15(),
                server_cert_obj.signature_hash_algorithm,
            )
            print("[Client] Server certificate verified.")
        except Exception as e:
            print("[Client] Server certificate verification failed:", e)
            s.close()
            return

        # Receive DH params from server
        dh_msg = recv_msg(s)
        if dh_msg.get("type") != "dh_params":
            print("[Client] Expected dh_params")
            s.close()
            return
        p = int(dh_msg["p"])
        g = int(dh_msg["g"])
        B = int(dh_msg["B"])

        # build parameters and generate client's private/public
        params = dh.DHParameterNumbers(p, g).parameters()
        client_priv = params.generate_private_key()
        A = client_priv.public_key().public_numbers().y
        # send A
        send_msg(s, {"type": "dh_pub", "A": str(A)})

        # compute shared key and derive AES key
        server_pub_numbers = dh.DHPublicNumbers(B, dh.DHParameterNumbers(p, g))
        server_pub_key = server_pub_numbers.public_key()
        shared = client_priv.exchange(server_pub_key)
        session_key = hashlib.sha256(shared).digest()
        print("[Client] Session key established.")

        # interaction loop: register/login
        while True:
            print("\n1) Register\n2) Login\n3) Quit")
            choice = input("Choice: ").strip()
            if choice == "1":
                username = input("username: ").strip()
                password = input("password: ").strip()
                pw_hash = hashlib.sha256(password.encode()).hexdigest()
                payload = {
                    "type": "register",
                    "username": username,
                    "password_hash": pw_hash,
                }
                enc = aes_gcm_encrypt(session_key, json.dumps(payload).encode())
                send_msg(s, {"type": "secure", "payload": enc})
                resp = recv_msg(s)
                if resp and resp.get("type") == "secure":
                    dec = aes_gcm_decrypt(session_key, resp["payload"])
                    print("[Server]", json.loads(dec.decode()))
            elif choice == "2":
                username = input("username: ").strip()
                password = input("password: ").strip()
                pw_hash = hashlib.sha256(password.encode()).hexdigest()
                payload = {
                    "type": "login",
                    "username": username,
                    "password_hash": pw_hash,
                }
                enc = aes_gcm_encrypt(session_key, json.dumps(payload).encode())
                send_msg(s, {"type": "secure", "payload": enc})
                resp = recv_msg(s)
                if resp and resp.get("type") == "secure":
                    dec = aes_gcm_decrypt(session_key, resp["payload"])
                    print("[Server]", json.loads(dec.decode()))
            elif choice == "3":
                print("Bye.")
                break
            else:
                print("Invalid option.")
        s.close()


if __name__ == "__main__":
    if not os.path.exists(CA_CERT):
        print("rootCA.crt not found. Start ca.py first.")
        exit(1)
    client = Client()
    client.start()
