"""Authenticated Mallory proxy used to demonstrate MITM prevention."""

import json
import os
import socket

from common import generate_private_key, compute_public_value, short
from pki_common import (
    private_key_from_pem,
    public_key_from_pem,
    build_handshake_message,
    parse_handshake_message,
    sign_dh_value,
)

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 7500
BOB_HOST = "127.0.0.1"
BOB_PORT = 7000
SOCKET_TIMEOUT = 10
MAX_LINE_SIZE = 64 * 1024
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def recv_line(sock):
    data = bytearray()
    while len(data) < MAX_LINE_SIZE:
        chunk = sock.recv(min(8192, MAX_LINE_SIZE - len(data)))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in chunk:
            return bytes(data).split(b"\n", 1)[0].strip()
    raise ValueError("Peer sent an oversized or incomplete line")


def main():
    with open(os.path.join(PKI_DIR, "alice_cert.json"), encoding="utf-8") as f:
        alice_cert = json.load(f)
    with open(os.path.join(PKI_DIR, "mallory_cert.json"), encoding="utf-8") as f:
        mallory_cert = json.load(f)
    with open(os.path.join(PKI_DIR, "mallory_identity_private.pem"), "rb") as f:
        mallory_identity_private = private_key_from_pem(f.read())

    print(f"[Mallory] Listening on {LISTEN_HOST}:{LISTEN_PORT}, posing as Bob.")
    print(f"[Mallory] Relaying toward Bob at {BOB_HOST}:{BOB_PORT}.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(SOCKET_TIMEOUT)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(1)

        alice_conn, addr = listener.accept()
        alice_conn.settimeout(SOCKET_TIMEOUT)
        print(f"[Mallory] Alice connected from {addr}.")

        with alice_conn, socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_conn:
            bob_conn.settimeout(SOCKET_TIMEOUT)
            bob_conn.connect((BOB_HOST, BOB_PORT))

            incoming = recv_line(alice_conn)
            real_alice_cert, _, _ = parse_handshake_message(incoming)
            print(f"[Mallory] Intercepted Alice's handshake as '{real_alice_cert['subject']}'.")

            print("\n" + "-" * 66)
            print("ATTEMPT 1: Replay Alice's certificate with Mallory's DH value")
            print("-" * 66)
            mallory_dh_private = generate_private_key()
            mallory_dh_public = compute_public_value(mallory_dh_private)
            forged_signature = sign_dh_value(mallory_identity_private, mallory_dh_public)
            bob_conn.sendall(build_handshake_message(alice_cert, mallory_dh_public, forged_signature))
            print(f"[Mallory] Sent Alice's certificate with Mallory's DH value {short(mallory_dh_public)}.")
            print("[Mallory] Signature uses Mallory's key, so Bob must reject it.")

            try:
                response = recv_line(bob_conn)
            except (socket.timeout, ValueError):
                response = b""
            if response:
                print("[Mallory] Unexpected Bob response: forged handshake was not rejected.")
            else:
                print("[Mallory] Bob closed the connection -- impersonation attempt blocked.")

        print("\n" + "-" * 66)
        print("ATTEMPT 2: Connect honestly as Mallory")
        print("-" * 66)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bob_conn2:
            bob_conn2.settimeout(SOCKET_TIMEOUT)
            bob_conn2.connect((BOB_HOST, BOB_PORT))
            mallory_dh_private = generate_private_key()
            mallory_dh_public = compute_public_value(mallory_dh_private)
            mallory_dh_sig = sign_dh_value(mallory_identity_private, mallory_dh_public)
            bob_conn2.sendall(build_handshake_message(mallory_cert, mallory_dh_public, mallory_dh_sig))
            print("[Mallory] Sent her own valid certificate and DH signature.")
            try:
                response = recv_line(bob_conn2)
                if response:
                    peer_cert, _, _ = parse_handshake_message(response)
                    print(f"[Mallory] Bob identified himself as '{peer_cert['subject']}'.")
            except (socket.timeout, ValueError):
                print("[Mallory] Bob did not complete the optional honest handshake response.")

    print("\n[Mallory] Alice was never impersonated; authenticated DH blocked substitution.")


if __name__ == "__main__":
    main()
