"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import os
import socket
import threading
from typing import Any, Optional
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from common.protocol import HelloMessage, DH_P_Q_Client, DH_Server_B
from common.utils import verify_server_certificate

from pydantic import BaseModel

HOST = "127.0.0.1"
PORT = 9000

CA_HOST = "127.0.0.1"
CA_PORT = 8000
server_cert = b""


class Server:
    def __init__(self):
        # 1. Generate RSA private and public key for Client
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = private_key.public_key()

        self.public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def _send_msg_from_model(self, msg: BaseModel):
        self.server.sendall(json.dumps(msg.dict()).encode())

    def _receive_msg_from_model(self, size: int = 4096) -> dict[str, Any]:
        received_data = self.server.recv(size)
        server_data = json.loads(received_data.decode())
        return server_data

    def _get_certificate(self):
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

    def _hand_shake(self):
        global server_cert

    def _generate_key()

    def _handle_client(self, conn, addr):
        global server_cert
        print(f"[NEW CONNECTION] {addr} connected.")
        client_hello: Optional[HelloMessage] = None
        try:
            data = conn.recv(4096)
            if not data:
                break

            received_data = self._receive_msg_from_model(4096)
            client_hello = HelloMessage(**received_data)
            print(f"[RECEIVED] Hello from {addr}: {client_hello}")

            server_hello: HelloMessage = HelloMessage(
                type="server_hello",
                cert=server_cert.decode(),
                nonce=os.urandom(16).hex(),  # type: ignore
            )
            self._send_msg_from_model(server_hello)
            verify_server_certificate(client_hello.cert.encode())

            received_data = self._receive_msg_from_model(4096)
            dh_client_things = DH_P_Q_Client(**received_data)
            b = os.urandom(4)
            B = (dh_client_things.g**b) % p
            server_data = DH_Server_B(B=B)
            self._send_msg_from_model(server_data)


            while True:
                data = conn.recv(4096)
                if not data:
                    break
        except ConnectionResetError:
            print(f"[DISCONNECTED] {addr} disconnected abruptly.")
        finally:
            conn.close()
            print(f"[DISCONNECTED] {addr} disconnected.")

    def boot_up(self):
        global server_cert
        server_cert = self.get_certificate()  # ger my certficate from CA
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((HOST, PORT))
        self.server.listen()

        while True:
            conn, addr = server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")


def main():
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")


if __name__ == "__main__":
    main()
