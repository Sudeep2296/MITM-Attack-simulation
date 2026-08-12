"""
Shared Diffie-Hellman parameters and cryptographic helpers.

Uses RFC 3526 Group 14 (2048-bit MODP) for the educational demo.
"""

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", "")

P = int(P_HEX, 16)
G = 2
MIN_DH_PUBLIC = 2
MAX_DH_PUBLIC = P - 2


def generate_private_key():
    """Generate a random 256-bit private DH exponent."""
    return int.from_bytes(os.urandom(32), "big")


def compute_public_value(private_key):
    """Compute g^private mod p."""
    if not 1 <= private_key < P:
        raise ValueError("Invalid DH private exponent")
    return pow(G, private_key, P)


def validate_public_value(public_value):
    """Reject malformed or obviously invalid peer DH public values."""
    if not isinstance(public_value, int) or not MIN_DH_PUBLIC <= public_value <= MAX_DH_PUBLIC:
        raise ValueError("Invalid DH public value")
    return public_value


def compute_shared_secret(their_public_value, my_private_key):
    """Compute and validate (their_public)^my_private mod p."""
    validate_public_value(their_public_value)
    if not 1 <= my_private_key < P:
        raise ValueError("Invalid DH private exponent")
    shared_secret = pow(their_public_value, my_private_key, P)
    if shared_secret == 1:
        raise ValueError("Invalid DH shared secret")
    return shared_secret


def derive_aes_key(shared_secret_int, salt=None, info=b"mitm-demo aes key"):
    """Derive an AES-256 key from the DH secret using HKDF-SHA256."""
    if shared_secret_int <= 0:
        raise ValueError("Invalid shared secret")
    secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, "big")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(secret_bytes)


def aes_encrypt(key, plaintext: bytes):
    """AES-256-GCM encrypt. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce, aesgcm.encrypt(nonce, plaintext, None)


def aes_decrypt(key, nonce, ciphertext: bytes):
    """AES-256-GCM decrypt. Raises if the key/tag is wrong."""
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def short(n: int, length=16) -> str:
    """Pretty-print a big integer as a short hex string for demo logs."""
    h = format(n, "x")
    return f"{h[:length]}...{h[-4:]} ({n.bit_length()} bits)"
