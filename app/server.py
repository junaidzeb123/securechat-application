import socket
import threading
import json
import os
import secrets
import base64
import hashlib
import time
from typing import Any
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization, hashes
from crypto.aes import aes_encrypt, aes_decrypt
from crypto.dh import dh_generate_private_key, dh_derive_shared_key
from common.protocol import HelloMessage, DH_P_Q_Client, DH_Server_B

HOST = "127.0.0.1"
PORT = 9000
SERVER_PRIVATE_KEY = "../certs/server_private_key.pem"
SERVER_CERT = "../certs/server_cert.crt"
CA_CERT = "../certs/rootCA.crt"

USER_DB = {}  # {username: password_hash}


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


def verify_cert_signed_by_ca(cert_pem: bytes, ca_cert: x509.Certificate) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem)
    ca_pub = ca_cert.public_key()
    ca_pub.verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )
    return True


class Server:
    def __init__(self):
        self._load_keys()

    def _load_keys(self):
        with open(SERVER_PRIVATE_KEY, "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), None)
        with open(SERVER_CERT, "rb") as f:
            self.cert_pem = f.read()
        with open(CA_CERT, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def perform_dh_key_exchange(self, conn):
        client_dh = DH_P_Q_Client(**recv_msg(conn))
        p, g = int(client_dh.p), int(client_dh.g)
        parameters = dh.DHParameterNumbers(p, g).parameters()
        priv = dh_generate_private_key(parameters)
        pub = priv.public_key()
        send_msg(conn, {"type": "dh_server", "B": str(pub.public_numbers().y)})
        client_pub = dh.DHPublicNumbers(int(client_dh.A), dh.DHParameterNumbers(p, g)).public_key()
        session_key = dh_derive_shared_key(priv, client_pub)[:16]  # AES-128
        return session_key

    def handle_client(self, conn, addr):
        try:
            hello = recv_msg(conn)
            client_cert_pem = hello["cert"].encode()
            verify_cert_signed_by_ca(client_cert_pem, self.ca_cert)

            server_nonce = secrets.token_bytes(16)
            send_msg(conn, {"type": "server_hello", "cert": self.cert_pem.decode(), "nonce": server_nonce.hex()})

            session_key = self.perform_dh_key_exchange(conn)
            print(f"[+] Session key ({addr}):", session_key.hex())

            seqno_expected = 1

            while True:
                msg = recv_msg(conn)
                if not msg:
                    break

                ct = base64.b64decode(msg["ct"])
                sig = base64.b64decode(msg["sig"])
                seqno, ts = msg["seqno"], msg["ts"]

                digest = hashlib.sha256(f"{seqno}{ts}".encode() + ct).digest()
                client_cert = x509.load_pem_x509_certificate(client_cert_pem)
                client_pub = client_cert.public_key()

                client_pub.verify(sig, digest, padding.PKCS1v15(), hashes.SHA256())

                plaintext = aes_decrypt(session_key, ct).decode()
                payload = json.loads(plaintext)
                print(f"[{addr}] Received:", payload)

                if payload["type"] == "register":
                    USER_DB[payload["username"]] = payload["password_hash"]
                    reply = {"status": "ok", "msg": "registered"}
                elif payload["type"] == "login":
                    if USER_DB.get(payload["username"]) == payload["password_hash"]:
                        reply = {"status": "ok", "msg": "login successful"}
                    else:
                        reply = {"status": "error", "msg": "invalid credentials"}
                elif payload["type"] == "chat":
                    print(f"[Chat from {addr}]: {payload['msg']}")
                    reply = {"status": "ok", "msg": "Message received"}
                else:
                    reply = {"status": "error", "msg": "unknown request"}

                # Server reply with same secure message format
                ct = aes_encrypt(session_key, json.dumps(reply).encode())
                ts = int(time.time() * 1000)
                seqno_expected += 1
                digest = hashlib.sha256(f"{seqno_expected}{ts}".encode() + ct).digest()
                sig = self.private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
                resp = {
                    "type": "msg",
                    "seqno": seqno_expected,
                    "ts": ts,
                    "ct": base64.b64encode(ct).decode(),
                    "sig": base64.b64encode(sig).decode(),
                }
                send_msg(conn, resp)

        except Exception as e:
            print("[!] Error:", e)
        finally:
            conn.close()

    def start(self):
        s = socket.socket()
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    Server().start()
