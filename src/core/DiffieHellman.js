import { modPow } from './CryptoUtils.js';

/**
 * Standard Diffie–Hellman Key Exchange Calculator & Model
 * Performs exact modular arithmetic calculations and prepares structured formulas and proofs.
 */
export class DiffieHellman {
  /**
   * @param {number|bigint} p Prime modulus
   * @param {number|bigint} g Generator base
   * @param {number|bigint} a Alice's private exponent
   * @param {number|bigint} b Bob's private exponent
   */
  constructor(p, g, a, b) {
    this.p = BigInt(p);
    this.g = BigInt(g);
    this.a = BigInt(a);
    this.b = BigInt(b);

    // 1. Calculate Public Keys
    this.A = modPow(this.g, this.a, this.p);
    this.B = modPow(this.g, this.b, this.p);

    // 2. Calculate Shared Secrets
    this.Ka = modPow(this.B, this.a, this.p);
    this.Kb = modPow(this.A, this.b, this.p);

    // 3. Verification
    this.isMatch = (this.Ka === this.Kb);
  }



  getMathDetails() {
    return {
      alicePublic: {
        title: "Alice Computes Public Key A",
        formula: 'A = gᵃ mod p',
        substituted: `A = ${this.g}ᵃ mod ${this.p} = ${this.g}^${this.a} mod ${this.p}`,
        value: this.A.toString(),
        displayEquation: `A = ${this.g}^${this.a} mod ${this.p} = ${this.A}`,
        explanation: `Alice exponentiates public generator g = ${this.g} with secret exponent a = ${this.a} modulo prime p = ${this.p}.`
      },
      bobPublic: {
        title: "Bob Computes Public Key B",
        formula: 'B = gᵇ mod p',
        substituted: `B = ${this.g}ᵇ mod ${this.p} = ${this.g}^${this.b} mod ${this.p}`,
        value: this.B.toString(),
        displayEquation: `B = ${this.g}^${this.b} mod ${this.p} = ${this.B}`,
        explanation: `Bob exponentiates public generator g = ${this.g} with secret exponent b = ${this.b} modulo prime p = ${this.p}.`
      },
      aliceSecret: {
        title: "Alice Derives Shared Secret K_Alice",
        formula: 'K_Alice = Bᵃ mod p',
        substituted: `K_Alice = ${this.B}ᵃ mod ${this.p} = ${this.B}^${this.a} mod ${this.p}`,
        value: this.Ka.toString(),
        displayEquation: `K_Alice = ${this.B}^${this.a} mod ${this.p} = ${this.Ka}`,
        explanation: `Alice takes Bob's public value B = ${this.B} and raises it to her secret exponent a = ${this.a} modulo ${this.p}.`
      },
      bobSecret: {
        title: "Bob Derives Shared Secret K_Bob",
        formula: 'K_Bob = Aᵇ mod p',
        substituted: `K_Bob = ${this.A}ᵇ mod ${this.p} = ${this.A}^${this.b} mod ${this.p}`,
        value: this.Kb.toString(),
        displayEquation: `K_Bob = ${this.A}^${this.b} mod ${this.p} = ${this.Kb}`,
        explanation: `Bob takes Alice's public value A = ${this.A} and raises it to his secret exponent b = ${this.b} modulo ${this.p}.`
      },
      proof: {
        formula: '(gᵇ)ᵃ ≡ gᵃᵇ ≡ (gᵃ)ᵇ (mod p)',
        summary: `Both parties derive identical shared secret K = ${this.Ka} over an unencrypted channel without revealing secret exponents a or b.`,
        discreteLogNote: 'Security rests on the Discrete Logarithm Problem (DLP): given g, p, and A = gᵃ mod p, determining exponent a is computationally infeasible for cryptographically large primes.'
      }
    };
  }

  /**
   * Get pedagogical 4-stage sequence for step-by-step examination (clean academic text)
   */
  getSteps() {
    return [
      {
        stage: 1,
        title: 'Public Parameter Agreement',
        entity: 'Alice & Bob',
        action: 'Public Domain Agreement',
        math: `p = ${this.p},  g = ${this.g}`,
        description: `Alice and Bob openly agree on prime modulus p = ${this.p} and primitive root generator g = ${this.g}. Eavesdroppers can observe both parameters without compromising security.`
      },
      {
        stage: 2,
        title: 'Private Exponent Selection',
        entity: 'Alice (a) & Bob (b)',
        action: 'Secret Generation (Local)',
        math: `a = ${this.a} (Alice secret),  b = ${this.b} (Bob secret)`,
        description: `Alice chooses secret integer a = ${this.a} and Bob chooses secret integer b = ${this.b}. These values remain strictly local and are never transmitted across the network.`
      },
      {
        stage: 3,
        title: 'Public Key Computation & Transmission',
        entity: 'Network Transmission',
        action: 'Exchange of A and B',
        math: `A = ${this.g}^${this.a} mod ${this.p} = ${this.A},  B = ${this.g}^${this.b} mod ${this.p} = ${this.B}`,
        description: `Alice computes A = ${this.A} and transmits it to Bob. Bob computes B = ${this.B} and transmits it to Alice. Observers cannot deduce private exponents due to the Discrete Logarithm Problem.`
      },
      {
        stage: 4,
        title: 'Independent Shared Secret Derivation',
        entity: 'Alice & Bob',
        action: 'Shared Key Agreement',
        math: `K = ${this.B}^${this.a} mod ${this.p} = ${this.A}^${this.b} mod ${this.p} = ${this.Ka}`,
        description: `Alice computes K = Bᵃ mod p = ${this.Ka}. Bob computes K = Aᵇ mod p = ${this.Kb}. Both arrive at the exact same symmetric key K = ${this.Ka}.`
      }
    ];
  }
}
