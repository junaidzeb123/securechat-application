"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import os
import socket
import threading
from typing import Any, Optional
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from common.protocol import HelloMessage
from common.utils import verify_server_certificate

HOST = "127.0.0.1"
PORT = 9000

CA_HOST = "127.0.0.1"
CA_PORT = 8000
server_cert = b""


# 1. Generate RSA private and public key for Client
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)


def get_certificate():
    public_pem_str = public_pem.decode("utf-8")
    request: dict[str, Any] = {
        "public_key": public_pem_str,
        "common_name": "server",
        "email": "server@example.com",
        "is_server": False,
    }

    # Get certificate info from CA
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((CA_HOST, CA_PORT))
        s.sendall(json.dumps(request).encode())
        my_cert = s.recv(8192)

    return my_cert


def hand_shake():
    global server_cert


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    client_hello: Optional[HelloMessage] = None
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            client_hello = HelloMessage(**json.loads(data.decode()))
            print(f"[RECEIVED] Hello from {addr}: {client_hello}")

            server_hello: HelloMessage = HelloMessage(
                type="server_hello",
                cert=server_cert.decode(),
                nonce=os.urandom(16).hex(),  # type: ignore
            )
            conn.sendall(json.dumps(server_hello.dict()).encode())
            verify_server_certificate(client_hello.cert.encode())

    except ConnectionResetError:
        print(f"[DISCONNECTED] {addr} disconnected abruptly.")
    finally:
        conn.close()
        print(f"[DISCONNECTED] {addr} disconnected.")


def main():
    global server_cert
    server_cert = get_certificate()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


if __name__ == "__main__":
    main()
