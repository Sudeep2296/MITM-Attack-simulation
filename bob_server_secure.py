"""
bob_server_secure.py
---------------------
Bob runs as a TCP server. This time, the DH exchange is authenticated:
Bob sends his CA-signed certificate along with his DH public value and
a signature over it; he verifies the same from whoever connects before
trusting their DH value.

Run this FIRST (after setup_ca.py has been run once):
    python3 bob_server_secure.py

Listens on 127.0.0.1:7000.
"""

import json
import os
import socket

from common import (
    generate_private_key,
    compute_public_value,
    compute_shared_secret,
    derive_aes_key,
    aes_decrypt,
    short,
)
from pki_common import (
    private_key_from_pem,
    public_key_from_pem,
    verify_certificate,
    sign_dh_value,
    verify_dh_signature,
    build_handshake_message,
    parse_handshake_message,
)

HOST = "127.0.0.1"
PORT = 7000
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def recv_line(conn):
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(8192)
        if not chunk:
            break
        data += chunk
    return data.strip()


def main():
    with open(os.path.join(PKI_DIR, "ca_public.pem"), "rb") as f:
        ca_public = public_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "bob_identity_private.pem"), "rb") as f:
        bob_identity_private = private_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "bob_cert.json")) as f:
        bob_cert = json.load(f)

    print(f"[Bob] Loaded his certificate and CA trust anchor.")
    print(f"[Bob] Listening for a connection on {HOST}:{PORT} ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(5)
        print("[Bob] (Server will handle connections one at a time, looping forever --")
        print("[Bob]  press Ctrl+C to stop.)\n")

        while True:
            conn, addr = srv.accept()
            handle_connection(conn, addr, ca_public, bob_identity_private, bob_cert)


def handle_connection(conn, addr, ca_public, bob_identity_private, bob_cert):
    with conn:
            print(f"[Bob] Connection received from {addr}. Beginning AUTHENTICATED DH exchange.\n")

            # Receive the other party's handshake message first
            incoming = recv_line(conn)
            if not incoming:
                print("[Bob] Peer disconnected before sending a handshake.\n")
                return
            peer_cert, peer_dh_public, peer_dh_signature = parse_handshake_message(incoming)
            print(f"[Bob] Received a handshake claiming to be '{peer_cert['subject']}'.")

            # --- Verification happens BEFORE Bob commits to responding ---
            # (Bob should never reveal his own DH value/signature to a peer
            # he has not yet authenticated.)
            if not verify_certificate(ca_public, peer_cert):
                print(f"[Bob] ✘ Certificate for '{peer_cert['subject']}' is NOT validly signed by the CA.")
                print("[Bob] ABORTING -- refusing to respond or proceed with the key exchange.\n")
                return
            print(f"[Bob] ✔ Certificate for '{peer_cert['subject']}' is validly CA-signed.")

            peer_identity_public = public_key_from_pem(peer_cert["public_key_pem"].encode())
            if not verify_dh_signature(peer_identity_public, peer_dh_public, peer_dh_signature):
                print(f"[Bob] ✘ DH value signature is INVALID for '{peer_cert['subject']}'.")
                print("[Bob] ABORTING -- refusing to respond. Someone tampered with or forged this DH value.\n")
                return
            print(f"[Bob] ✔ DH value signature verifies against '{peer_cert['subject']}''s certified key.\n")

            # --- Only now does Bob send his own handshake message back ---
            bob_dh_private = generate_private_key()
            bob_dh_public = compute_public_value(bob_dh_private)
            bob_dh_signature = sign_dh_value(bob_identity_private, bob_dh_public)
            conn.sendall(build_handshake_message(bob_cert, bob_dh_public, bob_dh_signature))
            print(f"[Bob] Peer authenticated successfully -- sent his own certificate, DH value, and signature.\n")

            # --- Proceed with the key exchange ---
            shared_secret = compute_shared_secret(peer_dh_public, bob_dh_private)
            print(f"[Bob] Computed shared secret: {short(shared_secret)}")
            key = derive_aes_key(shared_secret)

            msg_line = recv_line(conn)
            if not msg_line:
                print("[Bob] Peer disconnected before sending a message.\n")
                return
            nonce_hex, ct_hex = msg_line.decode().split(":")
            nonce, ciphertext = bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex)
            print(f"[Bob] Received encrypted message: {ct_hex[:60]}...")

            try:
                plaintext = aes_decrypt(key, nonce, ciphertext)
                print(f"\n[Bob] Decrypted message: {plaintext.decode()!r}\n")
            except Exception as e:
                print(f"\n[Bob] FAILED to decrypt message: {e}\n")

    print("[Bob] Connection closed.\n" + "=" * 60 + "\n")


if __name__ == "__main__":
    main()
