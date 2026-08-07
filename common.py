"""
common.py
---------
Shared Diffie-Hellman parameters and helper functions used across all
three phases of the project (basic DH, MITM attack, authenticated fix).

We use a standard, well-known 2048-bit MODP group (RFC 3526, Group 14)
as our public (p, g) parameters -- the same kind of group used in real
protocols like IKE/IPSec and SSH.
"""

import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Public Diffie-Hellman domain parameters (known to everyone, including
# the attacker -- this is normal; DH security does not depend on p, g
# being secret).
# ---------------------------------------------------------------------------

# RFC 3526 Group 14 - 2048-bit MODP prime
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


def generate_private_key():
    """Generate a random private DH exponent."""
    # 256 bits of randomness is plenty against a 2048-bit prime.
    return int.from_bytes(os.urandom(32), "big")


def compute_public_value(private_key):
    """Compute g^private mod p."""
    return pow(G, private_key, P)


def compute_shared_secret(their_public_value, my_private_key):
    """Compute (their_public)^my_private mod p."""
    return pow(their_public_value, my_private_key, P)


def derive_aes_key(shared_secret_int):
    """
    Turn the raw DH shared secret (a big integer) into a 256-bit AES key
    using SHA-256 as a simple KDF. In production you'd use a proper KDF
    like HKDF, but SHA-256 is sufficient to illustrate the concept.
    """
    secret_bytes = shared_secret_int.to_bytes((shared_secret_int.bit_length() + 7) // 8, "big")
    return hashlib.sha256(secret_bytes).digest()


def aes_encrypt(key, plaintext: bytes):
    """AES-256-GCM encrypt. Returns (nonce, ciphertext)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def aes_decrypt(key, nonce, ciphertext: bytes):
    """AES-256-GCM decrypt. Raises if the key/tag is wrong."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def short(n: int, length=16) -> str:
    """Pretty-print a big integer as a short hex string for demo logs."""
    h = format(n, "x")
    return f"{h[:length]}...{h[-4:]} ({n.bit_length()} bits)"
