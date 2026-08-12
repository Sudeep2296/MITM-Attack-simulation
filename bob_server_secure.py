"""Authenticated Bob server for the educational DH/PKI demo."""

import json
import os
import socket

from common import generate_private_key, compute_public_value, compute_shared_secret, derive_aes_key, aes_decrypt, short
from pki_common import private_key_from_pem, public_key_from_pem, verify_certificate, sign_dh_value, verify_dh_signature, build_handshake_message, parse_handshake_message

HOST = "127.0.0.1"
PORT = 7000
SOCKET_TIMEOUT = 10
MAX_LINE_SIZE = 64 * 1024
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def recv_line(conn):
    data = bytearray()
    while len(data) < MAX_LINE_SIZE:
        chunk = conn.recv(min(8192, MAX_LINE_SIZE - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            return bytes(data).split(b"\n", 1)[0].strip()
    raise ValueError("Peer sent an oversized or incomplete line")


def handle_connection(conn, addr, ca_public, bob_identity_private, bob_cert):
    conn.settimeout(SOCKET_TIMEOUT)
    with conn:
        print(f"[Bob] Connection received from {addr}.")
        try:
            incoming = recv_line(conn)
            if not incoming:
                print("[Bob] Peer disconnected before sending a handshake.")
                return
            peer_cert, peer_dh_public, peer_dh_signature = parse_handshake_message(incoming)
            subject = peer_cert.get("subject", "unknown")
            print(f"[Bob] Received a handshake claiming to be '{subject}'.")

            if not verify_certificate(ca_public, peer_cert):
                print(f"[Bob] ✘ Certificate for '{subject}' is invalid. Aborting.")
                return

            peer_identity_public = public_key_from_pem(peer_cert["public_key_pem"].encode("ascii"))
            if not verify_dh_signature(peer_identity_public, peer_dh_public, peer_dh_signature):
                print(f"[Bob] ✘ DH signature for '{subject}' is invalid. Aborting.")
                return

            bob_dh_private = generate_private_key()
            bob_dh_public = compute_public_value(bob_dh_private)
            bob_dh_signature = sign_dh_value(bob_identity_private, bob_dh_public)
            conn.sendall(build_handshake_message(bob_cert, bob_dh_public, bob_dh_signature))

            shared_secret = compute_shared_secret(peer_dh_public, bob_dh_private)
            key = derive_aes_key(shared_secret)
            print(f"[Bob] Authenticated '{subject}', shared secret: {short(shared_secret)}")

            msg_line = recv_line(conn)
            if not msg_line:
                print("[Bob] Peer disconnected before sending a message.")
                return
            parts = msg_line.decode("ascii").split(":")
            if len(parts) != 2:
                raise ValueError("Invalid encrypted message format")
            nonce = bytes.fromhex(parts[0])
            ciphertext = bytes.fromhex(parts[1])
            if len(nonce) != 12 or len(ciphertext) < 16:
                raise ValueError("Invalid AES-GCM payload")
            plaintext = aes_decrypt(key, nonce, ciphertext)
            print(f"[Bob] Decrypted message: {plaintext.decode('utf-8')!r}")
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError, socket.timeout) as exc:
            print(f"[Bob] Protocol error: {exc}")


def main():
    with open(os.path.join(PKI_DIR, "ca_public.pem"), "rb") as f:
        ca_public = public_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "bob_identity_private.pem"), "rb") as f:
        bob_identity_private = private_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "bob_cert.json"), encoding="utf-8") as f:
        bob_cert = json.load(f)

    print(f"[Bob] Listening on {HOST}:{PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((HOST, PORT))
        srv.listen(5)
        try:
            while True:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                handle_connection(conn, addr, ca_public, bob_identity_private, bob_cert)
        except KeyboardInterrupt:
            print("\n[Bob] Server stopped.")


if __name__ == "__main__":
    main()
