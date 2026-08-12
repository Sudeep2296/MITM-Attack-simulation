# Diffie-Hellman Key Exchange · MITM Attack · PKI Authentication

A hands-on demonstration of why unauthenticated Diffie-Hellman is vulnerable to Man-in-the-Middle (MITM) attacks, and how authentication with CA-signed identities and digital signatures prevents DH value substitution. Built as a Cryptography and Network Security mini project.

The project has two parts:
1. **Python socket implementation** — real TCP processes for Alice, Bob, and Mallory.
2. **Interactive browser GUI** — a standalone visualizer using the Web Crypto API.

## Project Structure

```text
.
├── common.py
├── pki_common.py
├── setup_ca.py
├── alice_client_secure.py
├── bob_server_secure.py
├── mallory_proxy_secure.py
├── dh_mitm_visualizer .html
├── README.md
├── .gitignore
└── pki/                 # generated locally; private keys are never committed
```

> The repository currently focuses on the authenticated socket demo and browser visualizer. Older documentation referring to `socket_demo/` and `socket_demo_secure/` is obsolete.

## Interactive GUI

Open `dh_mitm_visualizer .html` directly in a modern browser. It demonstrates the four combinations of attacker/authentication and visualizes DH values, certificates, signatures, and encrypted messages.

## Python Socket Demo

### Prerequisites

```bash
python -m pip install cryptography
```

### 1. Generate fresh demo PKI materials

Run this locally before the first demo:

```bash
python setup_ca.py
```

This creates fresh Alice, Bob, and Mallory identity keys and certificates. The CA private key is used only in memory and is **not** written to disk. Never commit generated `pki/*.pem` files.

### 2. Direct authenticated connection

Terminal 1:

```bash
python bob_server_secure.py
```

Terminal 2:

```bash
python alice_client_secure.py --port 7000
```

### 3. MITM attempt

Terminal 1:

```bash
python bob_server_secure.py
```

Terminal 2:

```bash
python mallory_proxy_secure.py
```

Terminal 3:

```bash
python alice_client_secure.py --port 7500
```

Mallory substitutes her own DH value while replaying Alice's certificate. Bob verifies the signature against Alice's certified public key and rejects the substitution. Mallory can still make an honest connection as **Mallory**, but cannot impersonate Alice.

## Security Model

The demo uses:

- RFC 3526 Group 14 2048-bit MODP Diffie-Hellman
- RSA-2048 identity keys
- RSA-PSS with SHA-256 signatures
- HKDF-SHA256 for deriving the AES key from the DH secret
- AES-256-GCM for authenticated encryption
- Simplified educational certificates signed by a local CA

The certificate format is intentionally simplified and is **not an implementation of X.509/TLS PKI**.

## Security Notes

- Generated private keys are ignored by Git and must remain local.
- If a private key was ever committed to a public repository, treat it as compromised and regenerate it.
- The CA private key is intentionally never persisted by `setup_ca.py`.
- Socket reads have bounded sizes and timeouts to reduce trivial resource-exhaustion issues.
- Received DH public values are range-checked before shared-secret computation.

## References

- Stallings, W. *Cryptography and Network Security: Principles and Practice.*
- [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) — More Modular Exponential (MODP) Diffie-Hellman groups for IKE
- [Python cryptography documentation](https://cryptography.io/)

## Future Scope

- Replace classical DH/RSA with ECDH/ECDSA.
- Add certificate expiry, issuer, and revocation checks.
- Use real X.509 certificates to model a TLS-style trust chain.
- Add automated tests for DH validation, signatures, certificate validation, and MITM detection.
- Run the demo across multiple machines in an isolated lab network.
