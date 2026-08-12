"""Generate demo PKI materials.

Private keys are generated locally and must not be committed to Git. The CA
private key is used only during setup and is deliberately not persisted.
"""

import json
import os

from pki_common import generate_identity_keypair, private_key_to_pem, public_key_to_pem, issue_certificate

PKI_DIR = os.path.join(os.path.dirname(__file__), "pki")


def save(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"  wrote {path}")


def save_cert(path, cert):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cert, f, indent=2)
    print(f"  wrote {path}")


def main():
    os.makedirs(PKI_DIR, exist_ok=True)

    print("Generating root CA keypair ...")
    ca_private = generate_identity_keypair()
    save(os.path.join(PKI_DIR, "ca_public.pem"), public_key_to_pem(ca_private.public_key()))

    for name in ("Alice", "Bob", "Mallory"):
        print(f"\nGenerating {name}'s identity keypair and certificate ...")
        private_key = generate_identity_keypair()
        filename = f"{name.lower()}_identity_private.pem"
        save(os.path.join(PKI_DIR, filename), private_key_to_pem(private_key))
        cert = issue_certificate(ca_private, name, private_key.public_key())
        save_cert(os.path.join(PKI_DIR, f"{name.lower()}_cert.json"), cert)

    print("\nDone. PKI materials are in:", PKI_DIR)
    print("The CA private key was used only in memory and was NOT written to disk.")
    print("Do not commit generated *.pem private keys to Git.")


if __name__ == "__main__":
    main()
