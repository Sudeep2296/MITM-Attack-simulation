# 🔐 Interactive Diffie–Hellman Key Exchange & MITM Simulator

A 2D educational laboratory for learning and demonstrating the Diffie–Hellman key exchange algorithm, group theory (primitive roots & multiplicative orders), and Man-in-the-Middle (MITM) attacks.

## 🚀 Quick Start

```bash
# Install dependencies
npm install

# Start local development server
npm run dev

# Build production bundle
npm run build
```

The application will be live at `http://localhost:5173/`.

---

## 🧮 Cryptographic Foundation & Mathematical Validation

### 1. Prime Modulus $p$
- Must be a prime integer $p \ge 3$.
- Educational primes included in dropdown: `5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 97`.
- **Inline Alert for non-primes**:
  `"Invalid modulus: p must be prime. Please select a prime number."`

### 2. Generator $g$ Validation
- A generator (primitive root) modulo $p$ must have multiplicative order $p - 1$:
  $$\operatorname{ord}_p(g) = p - 1$$
  Equivalently, for every prime factor $q$ of $p - 1$:
  $$g^{(p - 1) / q} \not\equiv 1 \pmod p$$
- When $p$ changes, the generator dropdown dynamically populates all integers $2 \le g \le p - 1$.
- Valid generators are listed first and clearly labeled.
- **Inline Alert for non-generators**:
  `"Invalid generator for the selected prime modulus."`
  accompanied by dynamically computed valid generator suggestion badges (e.g., for $p = 23$, suggestions: `5, 7, 10, 11, 14, 15, 17, 19, 20, 21`).

### 3. Private Exponents ($a$ and $b$)
- Standard educational range:
  $$1 \le a \le p - 2 \quad \text{and} \quad 1 \le b \le p - 2$$
- Exponent values $0$ or $p - 1$ yield trivial public values ($g^0 \equiv 1 \pmod p$ and $g^{p-1} \equiv 1 \pmod p$ by Fermat's Little Theorem).
- Dynamically populated dropdowns restrict choices to $1 \dots p - 2$ with strict range boundary validation.

### 4. Diffie–Hellman Calculations
1. **Alice Public Key**:
   $$A = g^a \bmod p$$
2. **Bob Public Key**:
   $$B = g^b \bmod p$$
3. **Alice Shared Secret**:
   $$K_{\text{Alice}} = B^a \bmod p = (g^b)^a \bmod p$$
4. **Bob Shared Secret**:
   $$K_{\text{Bob}} = A^b \bmod p = (g^a)^b \bmod p$$
5. **Mathematical Identity**:
   $$(g^b)^a \equiv g^{ab} \equiv (g^a)^b \pmod p \implies K_{\text{Alice}} = K_{\text{Bob}}$$

---

## 🕵️ Man-in-the-Middle (MITM) Attack Simulation

1. **Interception**:
   - Alice sends $A \to$ intercepted by Mallory.
   - Mallory substitutes $M_B = g^{m_B} \bmod p \to$ Bob (Bob believes it is $A$).
   - Bob sends $B \to$ intercepted by Mallory.
   - Mallory substitutes $M_A = g^{m_A} \bmod p \to$ Alice (Alice believes it is $B$).
2. **Split Shared Secrets**:
   - **Alice Tunnel**: $K_{A-M} = (M_A)^a \equiv A^{m_A} \pmod p$
   - **Bob Tunnel**: $K_{M-B} = (M_B)^b \equiv B^{m_B} \pmod p$
   - $K_{A-M} \ne K_{M-B}$ (Split secrets).
3. **Tampering**:
   - Mallory holds both keys and can decrypt, inspect, modify, and re-encrypt traffic undetected.
   - Interactive tampering simulator demonstrates this in real-time.

---

## 🎓 College Viva & Examination Reference

- **Why must $p$ be prime?** Prime modulus ensures $\mathbb{Z}^*_p$ forms a cyclic multiplicative group of order $p - 1$ where every element has a modular inverse.
- **What is the Discrete Logarithm Problem?** Computing $A = g^a \bmod p$ is efficient; finding $a$ given $A, g, p$ is computationally intractable for cryptographically large primes.
- **Why is Diffie–Hellman vulnerable to MITM?** Unauthenticated Diffie–Hellman provides confidentiality against passive eavesdroppers, but provides zero authentication or identity binding. Fixed in TLS 1.3 by signing public ephemeral keys with digital signatures (RSA-PSS or ECDSA) backed by PKI certificates.
