# Live Socket Demo: Authenticated DH Defeats the MITM Attack

This is the "fix" companion to `socket_demo/` — the same three-process,
real-TCP-socket setup, but now Alice and Bob authenticate their DH
public values with CA-signed certificates and digital signatures.
Running Mallory's exact same attack against this version gets her
caught in real time.

## Files
- `common.py` — shared DH parameters and crypto helpers
- `pki_common.py` — certificate issue/verify, DH-value signing/verifying, wire protocol helpers
- `setup_ca.py` — **run once first**: creates the CA, issues certificates to Alice and Bob, saves everything to `pki/`
- `bob_server_secure.py` — Bob: authenticated DH server, loops to handle multiple connections
- `alice_client_secure.py` — Alice: authenticated DH client
- `mallory_proxy_secure.py` — Mallory: attempts the same MITM attack as before and gets rejected

## Setup (do this once)

```bash
python3 setup_ca.py
```

This creates a `pki/` folder containing:
- `ca_public.pem` — the CA's public key (the trust anchor everyone loads)
- `alice_cert.json`, `alice_identity_private.pem` — Alice's certificate and private identity key
- `bob_cert.json`, `bob_identity_private.pem` — Bob's certificate and private identity key
- `mallory_identity_private.pem` — Mallory has a keypair, but **no certificate as Alice or Bob**
- `ca_private_FOR_DEMO_ONLY.pem` — used only so the demo can show Mallory requesting her *own* honest certificate live; a real CA private key would never be distributed like this

## How to run — no attacker (baseline)

**Terminal 1:**
```bash
python3 bob_server_secure.py
```

**Terminal 2:**
```bash
python3 alice_client_secure.py --port 7000
```

Both sides verify each other's certificate and signature, then complete the exchange normally.

## How to run — MITM attack attempt (gets blocked)

**Terminal 1 — Bob (loops, so it can handle multiple connection attempts):**
```bash
python3 bob_server_secure.py
```

**Terminal 2 — Mallory's proxy:**
```bash
python3 mallory_proxy_secure.py
```

**Terminal 3 — Alice, pointed at Mallory's port:**
```bash
python3 alice_client_secure.py --port 7500
```

## What happens

Mallory tries the exact same trick as in the unauthenticated demo:

1. **Attempt 1**: She intercepts Alice's real certificate and replays it to Bob, but substitutes her own DH public value (she doesn't have Alice's private key, so she can't produce a valid signature over it). **Bob's signature check fails and he aborts without even responding.** Alice's connection then closes with no response — the attack is detected and the exchange simply does not go through.

2. **Attempt 2**: Mallory requests her own honest certificate from the CA (as "Mallory") and connects to Bob transparently. This succeeds — but Bob's logs correctly show he's talking to **"Mallory," not "Alice."** No impersonation occurs. Alice's original message is never delivered to Bob under any false identity.

Compare this directly against `socket_demo/mallory_proxy.py`, where the identical interception strategy succeeds completely and silently, including message tampering that neither party detects.

## Why this matters for the report/demo

This mirrors exactly how TLS defeats MITM attacks against HTTPS: the
server signs its ephemeral key-exchange value, and that signature is
verified against a certificate chained back to a trusted root CA. An
attacker without the server's private key cannot forge a valid
signature, so a substituted key-exchange value is rejected before any
secret is ever shared with the attacker — exactly what you see happen
to Mallory here.
