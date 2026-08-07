"""
alice_client_secure.py
------------------------
Alice connects out and performs an authenticated DH exchange: she sends
her CA-signed certificate + DH value + signature, and verifies the same
from whoever she connects to before trusting the response.

Run this LAST:
    # Direct to Bob (no attacker):
    python3 alice_client_secure.py --port 7000

    # Through Mallory's proxy (attack demo):
    python3 alice_client_secure.py --port 7500
"""

import argparse
import json
import os
import socket

from common import (
    generate_private_key,
    compute_public_value,
    compute_shared_secret,
    derive_aes_key,
    aes_encrypt,
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
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=7000,
                         help="Port to connect to: Bob directly (7000) or Mallory's proxy (7500)")
    args = parser.parse_args()

    with open(os.path.join(PKI_DIR, "ca_public.pem"), "rb") as f:
        ca_public = public_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "alice_identity_private.pem"), "rb") as f:
        alice_identity_private = private_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "alice_cert.json")) as f:
        alice_cert = json.load(f)

    print(f"[Alice] Loaded her certificate and CA trust anchor.")
    print(f"[Alice] Connecting to {HOST}:{args.port} (believing this is Bob) ...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, args.port))
        print("[Alice] Connected. Beginning AUTHENTICATED DH exchange.\n")

        alice_dh_private = generate_private_key()
        alice_dh_public = compute_public_value(alice_dh_private)
        alice_dh_signature = sign_dh_value(alice_identity_private, alice_dh_public)

        sock.sendall(build_handshake_message(alice_cert, alice_dh_public, alice_dh_signature))
        print(f"[Alice] Sent her certificate, DH value, and signature.")

        data = b""
        while not data.endswith(b"\n"):
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk

        if not data.strip():
            print("[Alice] Connection closed with no valid response received.")
            print("[Alice] This means whoever she connected to never completed a")
            print("[Alice] valid authenticated handshake back to her -- the exchange")
            print("[Alice] did not go through. (In this demo: Mallory could not")
            print("[Alice] forge a response as 'Bob' without Bob's private key.)")
            return

        peer_cert, peer_dh_public, peer_dh_signature = parse_handshake_message(data.strip())
        print(f"[Alice] Received a handshake claiming to be '{peer_cert['subject']}'.\n")

        # --- Verification ---
        if not verify_certificate(ca_public, peer_cert):
            print(f"[Alice] ✘ Certificate for '{peer_cert['subject']}' is NOT validly signed by the CA.")
            print("[Alice] ABORTING -- refusing to proceed.")
            return
        print(f"[Alice] ✔ Certificate for '{peer_cert['subject']}' is validly CA-signed.")

        peer_identity_public = public_key_from_pem(peer_cert["public_key_pem"].encode())
        if not verify_dh_signature(peer_identity_public, peer_dh_public, peer_dh_signature):
            print(f"[Alice] ✘ DH value signature is INVALID for '{peer_cert['subject']}'.")
            print("[Alice] ABORTING -- someone tampered with or forged this DH value.")
            return
        print(f"[Alice] ✔ DH value signature verifies against '{peer_cert['subject']}''s certified key.\n")

        # --- Proceed with the key exchange ---
        shared_secret = compute_shared_secret(peer_dh_public, alice_dh_private)
        print(f"[Alice] Computed shared secret: {short(shared_secret)}")
        key = derive_aes_key(shared_secret)

        message = b"Hey Bob, my card PIN is 4471, don't tell anyone!"
        nonce, ciphertext = aes_encrypt(key, message)
        payload = f"{nonce.hex()}:{ciphertext.hex()}\n"
        sock.sendall(payload.encode())
        print(f"\n[Alice] Sent encrypted message: {ciphertext.hex()[:60]}...")
        print(f"[Alice] (Plaintext was: {message.decode()!r})")

    print("\n[Alice] Done.")


if __name__ == "__main__":
    main()
