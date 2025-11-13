import socket
import json
import os
import base64
import secrets
import hashlib
import time
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, dh
from crypto.aes import aes_encrypt, aes_decrypt
from crypto.dh import (
    dh_generate_parameters,
    dh_generate_private_key,
    dh_derive_shared_key,
)
from common.protocol import HelloMessage

HOST = "127.0.0.1"
PORT = 9000
CLIENT_PRIVATE_KEY = "../certs/client_private_key.pem"
CLIENT_CERT = "../certs/client_cert.crt"
CA_CERT = "../certs/rootCA.crt"


def send_msg(sock: socket.socket, obj: Any):
    data = json.dumps(obj).encode()
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_msg(sock: socket.socket):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    length = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode())


class Client:
    def __init__(self):
        with open(CLIENT_PRIVATE_KEY, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), None)
        with open(CLIENT_CERT, "rb") as f:
            self.cert_pem = f.read()
        with open(CA_CERT, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def perform_dh_key_exchange(self, s):
        params = dh_generate_parameters(generator=5, key_size=512)
        priv = dh_generate_private_key(params)
        pub = priv.public_key()
        p, g = params.parameter_numbers().p, params.parameter_numbers().g
        send_msg(
            s,
            {
                "type": "dh_client",
                "p": str(p),
                "g": str(g),
                "A": str(pub.public_numbers().y),
            },
        )

        server_dh = recv_msg(s)
        server_pub = dh.DHPublicNumbers(
            int(server_dh["B"]), dh.DHParameterNumbers(p, g)
        ).public_key()
        session_key = dh_derive_shared_key(priv, server_pub)[:16]
        return session_key

    def start(self):
        s = socket.socket()
        s.connect((HOST, PORT))

        hello = {
            "type": "hello",
            "cert": self.cert_pem.decode(),
            "nonce": secrets.token_bytes(16).hex(),
        }
        send_msg(s, hello)
        server_hello = recv_msg(s)
        print("[Client] Server cert received.")

        session_key = self.perform_dh_key_exchange(s)
        print("[+] Session key:", session_key.hex())

        print("\n1) Register\n2) Login\n3) Quit")
        ch = input("Choice: ").strip()
        if ch == "3":
            break

        username = input("Username: ").strip()
        password = input("Password: ").strip()
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        payload = {
            "type": "register" if ch == "1" else "login",
            "username": username,
            "password_hash": pw_hash,
        }

        ct = aes_encrypt(session_key, json.dumps(payload).encode())
        ts = int(time.time() * 1000)
        seqno = secrets.randbelow(100000)
        digest = hashlib.sha256(f"{seqno}{ts}".encode() + ct).digest()
        sig = self.private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())

        msg = {
            "type": "msg",
            "seqno": seqno,
            "ts": ts,
            "ct": base64.b64encode(ct).decode(),
            "sig": base64.b64encode(sig).decode(),
        }
        send_msg(s, msg)

        resp = recv_msg(s)
        if not resp:
            break
        ct = base64.b64decode(resp["ct"])
        plaintext = aes_decrypt(session_key, ct).decode()
        print("[Server reply]:", plaintext)

        while True:
            print("\n1) SendMsg\n2) Quit")
            ch = input("Choice: ").strip()
            if ch == "2":
                break

            message  = input("input msg: ").strip()
            


if __name__ == "__main__":
    Client().start()
