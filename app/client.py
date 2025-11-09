"""Client skeleton — plain TCP; no TLS. See assignment spec."""

from typing import Any
import socket
import os
import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from common.protocol import HelloMessage
from common.utils import verify_server_certificate

HOST = "127.0.0.1"
PORT = 9000

CA_HOST = "127.0.0.1"
CA_PORT = 8000
cert = b""

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


def get_nonce():
    return os.urandom(16)


def key_hand_shake():
    pass


def exchange_certificates(connection: socket.socket) -> HelloMessage:
    global cert
    cert = get_certificate()

    client_hello = HelloMessage(
        type="hello",
        cert=cert.decode(),
        nonce=get_nonce().hex(),  # type: ignore
    )
    connection.sendall(json.dumps(client_hello.dict()).encode())
    received_data = connection.recv(4096)
    server_data = json.loads(received_data.decode())
    print("client side ", server_data)
    server_hello = HelloMessage(**server_data)
    print(f"[RECEIVED] Server Hello: {server_hello}")

    if not verify_server_certificate(server_hello.cert.encode()):
        print("Server certificate verification failed. Terminating connection.")
        connection.close()
        exit(1)
    return server_hello


def boot_up():
    global cert
    cert = get_certificate()
    verify_server_certificate(cert)

    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((HOST, PORT))

    server_hello: HelloMessage = exchange_certificates(connection)
    print(f"Server Nonce: {server_hello.nonce}")
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
    boot_up()
