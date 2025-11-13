# server.py
import socket
import threading
import json
import os
import secrets
from typing import Any
from cryptography.hazmat.primitives.asymmetric import padding, dh
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from common.protocol import HelloMessage, DH_Server_B, DH_P_Q_Client
import hashlib
from crypto.aes import aes_encrypt, aes_decrypt, generate_aes_key


HOST = "127.0.0.1"
PORT = 9000
CA_HOST = "127.0.0.1"
CA_PORT = 8000
SERVER_PRIVATE_KEY = "../certs/server_private_key.pem"
SERVER_PUBLIC_KEY = "../certs/server_public_key.pem"
SERVER_CERT = "../certs/server_cert.crt"
CA_CERT = "../certs/rootCA.crt"


# Helpers: length-prefixed JSON messages
def send_msg(sock: socket.socket, obj: Any):
    data = json.dumps(obj.__dict__).encode()
    length = len(data).to_bytes(4, "big")
    print(data)
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
    ca_pub = ca_cert.public_key()
    try:
        ca_pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except Exception as e:
        print("[Server] Certificate verification failed:", e)
        return False


class Server:
    def __init__(self):
        self._load_keys_and_certificate()

    def _load_keys_and_certificate(self):
        # Load CA private key
        with open(SERVER_PRIVATE_KEY, "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(), password=None
            )

        with open(SERVER_PUBLIC_KEY, "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

        # Load CA certificate
        with open(SERVER_CERT, "rb") as f:
            self.server_cert = f.read()

        with open(CA_CERT, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

    def handle_client(self, conn: socket.socket, addr):
        print(f"[Server] Connection from {addr}")
        try:
            # Step 2: receive client hello (client cert + nonce)
            client_hello = recv_msg(conn)
            if client_hello is None:
                return
            client_cert_pem = client_hello["cert"].encode()
            client_nonce = bytes.fromhex(client_hello["nonce"])
            print("[Server] Received client hello, nonce:", client_hello["nonce"][:16])

            # verify client certificate against CA
            if not verify_cert_signed_by_ca(client_cert_pem, self.ca_cert):
                print("[Server] Client cert verification failed. Closing.")
                conn.close()
                return

            # Step 3: send server hello with nonce
            server_nonce = secrets.token_bytes(16)
            server_hello = HelloMessage(
                type="server_hello",
                cert=self.server_cert.decode(),
                nonce=server_nonce.hex(),
            )

            send_msg(conn, server_hello)

            # At this point both sides could sign each other's nonce to prove private key possession.
            # For simplicity we skip explicit signing step and proceed to ephemeral DH.

            # Step 4: Diffie-Hellman key exchange
            # Server generates parameters and its private key
            # """

            # receive client's A
            # Receive client's DH parameters
            client_dh = DH_P_Q_Client(**recv_msg(conn))
            if client_dh.type != "dh_client":
                print("[Server] Expected dh_client")
                return

            p = int(client_dh.p)
            g = int(client_dh.g)

            # Create parameters from client's p, g
            parameters = dh.DHParameterNumbers(p, g).parameters()
            server_priv = parameters.generate_private_key()
            server_pub = server_priv.public_key()
            server_pub_num = server_pub.public_numbers().y

            # Send server's public key
            dh_msg = DH_Server_B(type="dh_server", B=str(server_pub_num))
            send_msg(conn, dh_msg)

            # Compute shared secret
            client_pub_numbers = dh.DHPublicNumbers(
                int(client_dh.A), dh.DHParameterNumbers(p, g)
            )
            client_pub_key = client_pub_numbers.public_key()
            shared_key = server_priv.exchange(client_pub_key)
            session_key = hashlib.sha256(shared_key).digest()

            print("[Server] Session key established.", session_key.hex())

            # Now loop to decrypt incoming secure messages
            while True:
                msg = recv_msg(conn)
                if msg is None:
                    break
                if msg.get("type") != "secure":
                    continue
                enc = msg["payload"]
                try:
                    plaintext = aes_gcm_decrypt(session_key, enc)
                    payload = json.loads(plaintext.decode())
                    typ = payload.get("type")
                    if typ == "register":
                        username = payload["username"]
                        pw_hash = payload["password_hash"]
                        if username in USER_DB:
                            res = {"status": "error", "message": "user exists"}
                        else:
                            USER_DB[username] = pw_hash
                            res = {"status": "ok", "message": "registered"}
                        send_msg(
                            conn,
                            {
                                "type": "secure",
                                "payload": aes_gcm_encrypt(
                                    session_key, json.dumps(res).encode()
                                ),
                            },
                        )
                    elif typ == "login":
                        username = payload["username"]
                        pw_hash = payload["password_hash"]
                        stored = USER_DB.get(username)
                        if stored is None or stored != pw_hash:
                            res = {"status": "error", "message": "invalid credentials"}
                        else:
                            res = {"status": "ok", "message": "login successful"}
                        send_msg(
                            conn,
                            {
                                "type": "secure",
                                "payload": aes_gcm_encrypt(
                                    session_key, json.dumps(res).encode()
                                ),
                            },
                        )
                    else:
                        res = {"status": "error", "message": "unknown request"}
                        send_msg(
                            conn,
                            {
                                "type": "secure",
                                "payload": aes_gcm_encrypt(
                                    session_key, json.dumps(res).encode()
                                ),
                            },
                        )
                except Exception as e:
                    print("[Server] Decrypt/process error:", e)
                    break
                # """
        except ConnectionError:
            print("[Server] Connection closed by client.")
        finally:
            conn.close()
            print(f"[Server] Disconnected {addr}")

    def start(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((HOST, PORT))
        s.listen()
        print(f"[Server] Listening on {HOST}:{PORT}")
        try:
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=self.handle_client, args=(conn, addr))
                t.start()
        except KeyboardInterrupt:
            print("[Server] Stopping.")
        finally:
            s.close()


if __name__ == "__main__":
    # Ensure CA cert exists
    if not os.path.exists(CA_CERT):
        print("rootCA.crt not found. Start ca.py first.")
        exit(1)
    server = Server()
    server.start()
