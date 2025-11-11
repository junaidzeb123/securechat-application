"""Client skeleton — plain TCP; no TLS. See assignment spec."""

from typing import Any
import socket
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from common.protocol import HelloMessage, DH_P_Q_Client
from common.utils import verify_server_certificate
from pydantic import BaseModel

HOST = "127.0.0.1"
PORT = 9000

CA_HOST = "127.0.0.1"
CA_PORT = 8000
cert = b""


class Client:
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
        self.connection.sendall(json.dumps(msg.dict()).encode())

    def _receive_msg_from_model(self, size: int = 4096) -> dict[str, Any]:
        received_data = self.connection.recv(size)
        server_data = json.loads(received_data.decode())
        return server_data

    def _get_certificate(self):
        public_pem_str = public_pem.decode("utf-8")
        request: dict[str, Any] = {
            "public_key": public_pem_str,
            "common_name": "Alice",
            "email": "alice@example.com",
            "is_server": False,
        }
        # Get certificate info from CA
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((CA_HOST, CA_PORT))
            s.sendall(json.dumps(request).encode())
            my_cert = s.recv(8192)
        return my_cert

    def _get_nonce(self):
        return os.urandom(16)

    def __isvalid_certificate(self, server_hello: HelloMessage):
        if not verify_server_certificate(server_hello.cert.encode()):
            print("Server certificate verification failed. Terminating connection.")
            connection.close()
            exit(1)
        return True

    def _exchange_certificates(self) -> HelloMessage:
        global cert
        cert = self.get_certificate()

        client_hello = HelloMessage(
            type="hello",
            cert=cert.decode(),
            nonce=self.get_nonce().hex(),  # type: ignore
        )
        self._send_msg_from_model(client_hello)
        server_data = self._receive_msg_from_model(4096)
        server_hello = HelloMessage(**server_data)
        print(f"[RECEIVED] Server Hello: {server_hello}")

        self.__isvalid_certificate(server_data)
        return server_hello

    def _generate_p_and_g(self):
        return os.urandom(16), os.urandom(16)

    def _generate_public_value(self, p: int, q: int, a: int):
        return (q**a) % p

    def exchange_DH_key(self):
        p, q = self._generate_p_and_g()
        a = os.urandom()
        p_key = _generate_public_value(p, q, a)
        msg = DH_P_Q_Client(p, q, a)
        self._send_msg_from_model(msg)
        received_data = self._receive_msg_from_model(4096)


    def boot_up(self):
        global cert
        cert = self._get_certificate()  # Get my certificat form CA
        verify_server_certificate(cert)  # verify my own certficate

        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((HOST, PORT))

        # ------------------ exchnage the certificate ---------------- #
        server_hello: HelloMessage = self._exchange_certificates()
        print(f"Server Nonce: {server_hello.nonce}")

        # -------------------- START KEY EXCHANING PROCESS ------------- #
        self.exchange_DH_key()
        # ------------------- Run Client -------------------

        print("Enter your choice:")
        print("1. Register\n2. Login\n")
        choice = int(input("Choice: "))

        if choice == 1:
            print("Register selected.")
            # Implement registration logic here
        elif choice == 2:
            print("Login selected.")
            # Implement login logic here
        else:
            print("Invalid choice.")

    # def start_client():
    #     client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     client.connect((HOST, PORT))
    #     print(f"Connected to server at {HOST}:{PORT}")

    #     try:
    #         while True:
    #             msg = input("Enter message: ")
    #             if msg.lower() == "exit":
    #                 break
    #             client.send(msg.encode())
    #             response = client.recv(1024).decode()
    #             print(f"[Server] {response}")
    #     finally:
    #         client.close()
    #         print("Disconnected from server.")


if __name__ == "__main__":
    client = Client()
    client.boot_up()
