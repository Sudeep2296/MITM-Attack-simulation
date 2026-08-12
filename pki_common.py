"""Helpers for the simplified educational PKI used by the socket demo."""

import json

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)
MAX_HANDSHAKE_SIZE = 64 * 1024
MAX_SUBJECT_LENGTH = 64
MAX_SIGNATURE_BYTES = 512


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


def issue_certificate(ca_private_key, subject_name: str, subject_public_key) -> dict:
    if not subject_name or len(subject_name) > MAX_SUBJECT_LENGTH:
        raise ValueError("Invalid certificate subject")
    pub_pem = public_key_to_pem(subject_public_key)
    payload = subject_name.encode("utf-8") + pub_pem
    signature = ca_private_key.sign(payload, PSS_PADDING, hashes.SHA256())
    return {
        "subject": subject_name,
        "public_key_pem": pub_pem.decode("ascii"),
        "signature_hex": signature.hex(),
    }


def verify_certificate(ca_public_key, cert: dict) -> bool:
    try:
        subject = cert["subject"]
        public_key_pem = cert["public_key_pem"]
        signature_hex = cert["signature_hex"]
        if not isinstance(subject, str) or not 1 <= len(subject) <= MAX_SUBJECT_LENGTH:
            return False
        if not isinstance(public_key_pem, str) or len(public_key_pem) > 4096:
            return False
        if not isinstance(signature_hex, str) or len(signature_hex) > MAX_SIGNATURE_BYTES * 2:
            return False
        payload = subject.encode("utf-8") + public_key_pem.encode("ascii")
        ca_public_key.verify(bytes.fromhex(signature_hex), payload, PSS_PADDING, hashes.SHA256())
        public_key_from_pem(public_key_pem.encode("ascii"))
        return True
    except (KeyError, ValueError, TypeError, UnicodeError, InvalidSignature):
        return False


def sign_dh_value(identity_private_key, dh_public_value: int) -> bytes:
    return identity_private_key.sign(str(dh_public_value).encode("ascii"), PSS_PADDING, hashes.SHA256())


def verify_dh_signature(identity_public_key, dh_public_value: int, signature: bytes) -> bool:
    try:
        if not isinstance(signature, bytes) or len(signature) > MAX_SIGNATURE_BYTES:
            return False
        identity_public_key.verify(signature, str(dh_public_value).encode("ascii"), PSS_PADDING, hashes.SHA256())
        return True
    except (InvalidSignature, TypeError, ValueError):
        return False


def build_handshake_message(cert: dict, dh_public_value: int, dh_signature: bytes) -> bytes:
    msg = {
        "cert": cert,
        "dh_public": str(dh_public_value),
        "dh_signature_hex": dh_signature.hex(),
    }
    encoded = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_HANDSHAKE_SIZE:
        raise ValueError("Handshake message too large")
    return encoded


def parse_handshake_message(line: bytes):
    if not line or len(line) > MAX_HANDSHAKE_SIZE:
        raise ValueError("Invalid or oversized handshake")
    msg = json.loads(line.decode("utf-8"))
    if not isinstance(msg, dict):
        raise ValueError("Invalid handshake object")
    cert = msg["cert"]
    dh_public_value = int(msg["dh_public"])
    dh_signature = bytes.fromhex(msg["dh_signature_hex"])
    if not isinstance(cert, dict) or len(dh_signature) > MAX_SIGNATURE_BYTES:
        raise ValueError("Invalid handshake fields")
    return cert, dh_public_value, dh_signature
