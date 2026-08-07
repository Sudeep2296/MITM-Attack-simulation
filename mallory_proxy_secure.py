"""
mallory_proxy_secure.py
-------------------------
Mallory attempts EXACTLY the same attack as in the unauthenticated demo
(mallory_proxy.py): sit between Alice and Bob, substitute her own DH
values on both legs. But now both legs are authenticated, so she has
two options, and we demonstrate both fail to impersonate anyone:

  Attempt 1: Forward her own DH value to Bob while replaying Alice's
             real certificate (certificates are public, easy to copy).
             She cannot produce a valid signature over her substituted
             DH value using Alice's identity key (she doesn't have it),
             so Bob's signature check fails and he aborts.

  Attempt 2: Request her OWN honest certificate from the CA (as
             "Mallory") and use that instead. The certificate and
             signature both verify correctly -- but Bob now knows he
             is talking to "Mallory", not "Alice". No impersonation
             occurs; the connection is transparently who it says it is.

Run this SECOND, after bob_server_secure.py is listening, and BEFORE
alice_client_secure.py connects to Mallory's port (7500).

    python3 mallory_proxy_secure.py
"""

import json
import os
import socket

from common import generate_private_key, compute_public_value, short
from pki_common import (
    private_key_from_pem,
    public_key_from_pem,
    verify_certificate,
    issue_certificate,
    sign_dh_value,
    verify_dh_signature,
    build_handshake_message,
    parse_handshake_message,
)

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 7500      # Alice connects here, thinking it's Bob
BOB_HOST = "127.0.0.1"
BOB_PORT = 7000          # The real Bob
PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def recv_line(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(8192)
        if not chunk:
            break
        data += chunk
    return data.strip()


def main():
    with open(os.path.join(PKI_DIR, "ca_public.pem"), "rb") as f:
        ca_public = public_key_from_pem(f.read())
    with open(os.path.join(PKI_DIR, "alice_cert.json")) as f:
        alice_cert = json.load(f)   # Public info -- Mallory can freely obtain this
    with open(os.path.join(PKI_DIR, "mallory_identity_private.pem"), "rb") as f:
        mallory_identity_private = private_key_from_pem(f.read())
    # NOTE: Mallory does NOT have alice_identity_private.pem or
    # bob_identity_private.pem -- those never leave Alice's/Bob's machines.
    # This is the entire point of the demo.

    print(f"[Mallory] Listening on {LISTEN_HOST}:{LISTEN_PORT}, posing as Bob.")
    print(f"[Mallory] Will relay onward to the real Bob at {BOB_HOST}:{BOB_PORT}.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(1)

        alice_conn, addr = listener.accept()
        print(f"[Mallory] Alice connected from {addr}, believing this is Bob.")

        with alice_conn:
            bob_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bob_conn.connect((BOB_HOST, BOB_PORT))
            print(f"[Mallory] Opened her own connection to the real Bob.\n")

            with bob_conn:
                # Receive Alice's real handshake (her real cert + real signed DH value)
                incoming = recv_line(alice_conn)
                real_alice_cert, real_alice_dh_public, real_alice_dh_sig = parse_handshake_message(incoming)
                print(f"[Mallory] Intercepted Alice's real handshake (cert subject: "
                      f"'{real_alice_cert['subject']}').")

                # --- ATTEMPT 1: substitute her own DH value, replay Alice's cert ---
                print("\n" + "-" * 66)
                print("ATTEMPT 1: Replay Alice's public certificate, but substitute")
                print("           Mallory's own DH value (she cannot sign as Alice).")
                print("-" * 66)

                mallory_dh_private_1 = generate_private_key()
                mallory_dh_public_1 = compute_public_value(mallory_dh_private_1)

                # Mallory does NOT have Alice's private key. The best she can do is
                # sign with her OWN key (forged/mismatched) -- this WILL fail
                # verification against Alice's certified public key.
                forged_signature = sign_dh_value(mallory_identity_private, mallory_dh_public_1)

                bob_conn.sendall(build_handshake_message(real_alice_cert, mallory_dh_public_1, forged_signature))
                print(f"[Mallory] Forwarded to Bob: Alice's real certificate + Mallory's own")
                print(f"          substituted DH value {short(mallory_dh_public_1)}, signed with")
                print(f"          Mallory's own key (NOT Alice's).")

                bob_response = recv_line(bob_conn)
                if not bob_response:
                    print("\n[Mallory] Bob closed the connection immediately -- ATTACK ATTEMPT 1 FAILED.")
                    print("          (Bob's signature check rejected the forged DH value.)")
                else:
                    print("\n[Mallory] Unexpected: Bob responded. Attempt 1 may have succeeded (it should not).")
                    return

            # --- ATTEMPT 2: get Mallory's own honest certificate, be transparent ---
            print("\n" + "-" * 66)
            print("ATTEMPT 2: Request Mallory's OWN certificate from the CA and")
            print("           connect to Bob honestly as 'Mallory' instead.")
            print("-" * 66)

            # Simulate Mallory requesting her own certificate from the CA
            # (this uses the CA's private key exactly as a real CA server would
            # when Mallory enrolls -- Mallory herself never touches this key)
            with open(os.path.join(PKI_DIR, "ca_private_FOR_DEMO_ONLY.pem"), "rb") as f:
                ca_private_for_issuing = private_key_from_pem(f.read())
            mallory_cert = issue_certificate(ca_private_for_issuing, "Mallory", mallory_identity_private.public_key())
            print("[Mallory] Obtained her own honest certificate for subject 'Mallory'.")

            bob_conn2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bob_conn2.connect((BOB_HOST, BOB_PORT))

            mallory_dh_private_2 = generate_private_key()
            mallory_dh_public_2 = compute_public_value(mallory_dh_private_2)
            mallory_dh_sig_2 = sign_dh_value(mallory_identity_private, mallory_dh_public_2)

            bob_conn2.sendall(build_handshake_message(mallory_cert, mallory_dh_public_2, mallory_dh_sig_2))
            print("[Mallory] Sent Bob her own valid certificate + correctly signed DH value.")

            bob_response2 = recv_line(bob_conn2)
            if bob_response2:
                peer_cert, peer_dh_public, peer_dh_sig = parse_handshake_message(bob_response2)
                cert_ok = verify_certificate(ca_public, peer_cert)
                print(f"\n[Mallory] Bob responded and identified himself as '{peer_cert['subject']}'.")
                print(f"[Mallory] This is a normal, transparent connection between Bob and 'Mallory'.")
                print(f"          Bob's logs will show he is talking to 'Mallory', NOT 'Alice'.")
                print(f"          Alice's original message was never delivered, and no")
                print(f"          impersonation of Alice occurred.")
            bob_conn2.close()

    print("\n[Mallory] Both attack attempts failed to impersonate Alice.")
    print("          Alice, still waiting on her original connection, will see it")
    print("          fail/hang because Mallory never completed a valid handshake as Bob.")


if __name__ == "__main__":
    main()
