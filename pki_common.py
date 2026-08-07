"""
pki_common.py
-------------
Helper functions for the simplified PKI used in the authenticated socket
demo: RSA key (de)serialization, certificate issuing/verification, and
signing/verifying DH public values. Shared by setup_ca.py, bob_server_secure.py,
alice_client_secure.py, and mallory_proxy_secure.py.

A "certificate" here is just a JSON-friendly dict:
    {
        "subject": "Alice",
        "public_key_pem": "<PEM string of Alice's identity public key>",
        "signature_hex": "<hex CA signature over subject + public_key_pem>"
    }
"""

import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


# --- Key (de)serialization -------------------------------------------------

def generate_identity_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def private_key_to_pem(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


def public_key_to_pem(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_from_pem(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


# --- Certificate issuing / verification ------------------------------------

def issue_certificate(ca_private_key, subject_name: str, subject_public_key) -> dict:
    pub_pem = public_key_to_pem(subject_public_key)
    payload = subject_name.encode() + pub_pem
    signature = ca_private_key.sign(payload, PSS_PADDING, hashes.SHA256())
    return {
        "subject": subject_name,
        "public_key_pem": pub_pem.decode(),
        "signature_hex": signature.hex(),
    }


def verify_certificate(ca_public_key, cert: dict) -> bool:
    payload = cert["subject"].encode() + cert["public_key_pem"].encode()
    try:
        ca_public_key.verify(bytes.fromhex(cert["signature_hex"]), payload, PSS_PADDING, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# --- Signing / verifying DH public values -----------------------------------

def sign_dh_value(identity_private_key, dh_public_value: int) -> bytes:
    message = str(dh_public_value).encode()
    return identity_private_key.sign(message, PSS_PADDING, hashes.SHA256())


def verify_dh_signature(identity_public_key, dh_public_value: int, signature: bytes) -> bool:
    message = str(dh_public_value).encode()
    try:
        identity_public_key.verify(signature, message, PSS_PADDING, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# --- Wire protocol helpers ---------------------------------------------------
# Each party sends one JSON line containing their certificate, DH public
# value, and the signature over that DH value.

def build_handshake_message(cert: dict, dh_public_value: int, dh_signature: bytes) -> bytes:
    msg = {
        "cert": cert,
        "dh_public": str(dh_public_value),
        "dh_signature_hex": dh_signature.hex(),
    }
    return (json.dumps(msg) + "\n").encode()


def parse_handshake_message(line: bytes):
    msg = json.loads(line.decode())
    cert = msg["cert"]
    dh_public_value = int(msg["dh_public"])
    dh_signature = bytes.fromhex(msg["dh_signature_hex"])
    return cert, dh_public_value, dh_signature
