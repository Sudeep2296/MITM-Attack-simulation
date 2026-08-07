"""
setup_ca.py
-----------
Run this ONCE before running the secure socket demo. It simulates the
"enrollment" phase that happens out-of-band in real PKI (e.g. when you
first set up HTTPS on a server and get a certificate from a CA):

    1. Creates a root CA with its own RSA keypair.
    2. Creates identity RSA keypairs for Alice, Bob, and Mallory.
    3. Has the CA issue signed certificates for Alice and Bob only.
       (Mallory does NOT get a certificate as "Alice" or "Bob" --
       she could get her own honest "Mallory" certificate, but that's
       simulated later inside mallory_proxy_secure.py itself.)
    4. Saves everything to the pki/ folder so the other scripts (each
       a separate process) can load it from disk.

Usage:
    python3 setup_ca.py
"""

import json
import os

from pki_common import (
    generate_identity_keypair,
    private_key_to_pem,
    public_key_to_pem,
    issue_certificate,
)

PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def save(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {path}")


def main():
    os.makedirs(PKI_DIR, exist_ok=True)

    print("Generating root CA keypair ...")
    ca_private = generate_identity_keypair()
    ca_public = ca_private.public_key()
    save(os.path.join(PKI_DIR, "ca_public.pem"), public_key_to_pem(ca_public))
    # (We keep the CA private key only transiently in this script -- in
    # real life it would never leave the CA's own secure environment.
    # We don't even write it to disk here to emphasize that no other
    # party should ever have it.)

    print("\nGenerating Alice's identity keypair and certificate ...")
    alice_private = generate_identity_keypair()
    save(os.path.join(PKI_DIR, "alice_identity_private.pem"), private_key_to_pem(alice_private))
    alice_cert = issue_certificate(ca_private, "Alice", alice_private.public_key())
    with open(os.path.join(PKI_DIR, "alice_cert.json"), "w") as f:
        json.dump(alice_cert, f, indent=2)
    print(f"  wrote {os.path.join(PKI_DIR, 'alice_cert.json')}")

    print("\nGenerating Bob's identity keypair and certificate ...")
    bob_private = generate_identity_keypair()
    save(os.path.join(PKI_DIR, "bob_identity_private.pem"), private_key_to_pem(bob_private))
    bob_cert = issue_certificate(ca_private, "Bob", bob_private.public_key())
    with open(os.path.join(PKI_DIR, "bob_cert.json"), "w") as f:
        json.dump(bob_cert, f, indent=2)
    print(f"  wrote {os.path.join(PKI_DIR, 'bob_cert.json')}")

    print("\nGenerating Mallory's identity keypair (NOT certified as Alice or Bob) ...")
    mallory_private = generate_identity_keypair()
    save(os.path.join(PKI_DIR, "mallory_identity_private.pem"), private_key_to_pem(mallory_private))
    print("  (Mallory's own honest certificate, if she requests one, is issued live")
    print("   inside mallory_proxy_secure.py to demonstrate the CA would only ever")
    print("   certify her as 'Mallory', never as 'Alice' or 'Bob'.)")

    # We also need to hand the CA's private key to the running mallory demo
    # ONLY so it can optionally issue Mallory her own honest certificate live,
    # exactly as a real CA server would if she requested one. We save it
    # separately and clearly labeled to make this explicit in the code/report.
    save(os.path.join(PKI_DIR, "ca_private_FOR_DEMO_ONLY.pem"), private_key_to_pem(ca_private))

    print("\nDone. PKI materials are in:", PKI_DIR)
    print("Alice and Bob each have a CA-signed certificate.")
    print("Mallory has an identity keypair but no certificate as Alice or Bob.")


if __name__ == "__main__":
    main()
