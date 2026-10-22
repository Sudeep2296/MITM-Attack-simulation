/**
 * Cryptographic & Number-Theoretic Utilities for Diffie-Hellman Key Exchange
 * 
 * Implements:
 * - Accurate BigInt modular exponentiation (modPow)
 * - Deterministic primality testing
 * - Multiplicative order calculation modulo p
 * - Primitive root / generator verification
 * - Dynamic generator search and classification
 * - Strict parameter boundary validation (1 <= a, b <= p - 2)
 */

/**
 * Standard list of small prime numbers for classroom and viva demonstrations
 */
export const SUGGESTED_PRIMES = [
  5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 97
];

/**
 * Fast modular exponentiation: (base^exponent) mod modulus
 * Uses native BigInt to guarantee arbitrary precision and zero overflow.
 * 
 * @param {number|bigint|string} base 
 * @param {number|bigint|string} exponent 
 * @param {number|bigint|string} modulus 
 * @returns {bigint}
 */
export function modPow(base, exponent, modulus) {
  base = BigInt(base);
  exponent = BigInt(exponent);
  modulus = BigInt(modulus);

  if (modulus <= 0n) {
    throw new RangeError('Modulus must be a positive integer');
  }
  if (modulus === 1n) {
    return 0n;
  }
  if (exponent < 0n) {
    throw new RangeError('Negative exponents are not supported in standard modPow');
  }

  let result = 1n;
  base = ((base % modulus) + modulus) % modulus;

  while (exponent > 0n) {
    if (exponent % 2n === 1n) {
      result = (result * base) % modulus;
    }
    base = (base * base) % modulus;
    exponent = exponent / 2n;
  }

  return result;
}

/**
 * Deterministic primality test for educational integers
 * 
 * @param {number|bigint} n 
 * @returns {boolean}
 */
export function isPrime(n) {
  const num = Number(n);
  if (!Number.isInteger(num) || num < 2) return false;
  if (num === 2 || num === 3) return true;
  if (num % 2 === 0 || num % 3 === 0) return false;

  for (let i = 5; i * i <= num; i += 6) {
    if (num % i === 0 || num % (i + 2) === 0) {
      return false;
    }
  }
  return true;
}

/**
 * Extract distinct prime factors of an integer n
 * 
 * @param {number} n 
 * @returns {number[]}
 */
export function getPrimeFactors(n) {
  let num = Math.floor(Math.abs(Number(n)));
  const factors = new Set();
  let d = 2;
  while (d * d <= num) {
    if (num % d === 0) {
      factors.add(d);
      while (num % d === 0) {
        num /= d;
      }
    }
    d++;
  }
  if (num > 1) {
    factors.add(num);
  }
  return Array.from(factors);
}

/**
 * Calculate the multiplicative order of integer g modulo prime p
 * The order is the smallest integer k >= 1 such that g^k === 1 (mod p).
 * 
 * @param {number} g 
 * @param {number} p 
 * @returns {number}
 */
export function getOrder(g, p) {
  g = Number(g);
  p = Number(p);
  if (!isPrime(p) || g <= 0 || g >= p) return 0;
  
  // Find order by testing divisors of p - 1
  const phi = p - 1;
  const factors = getPrimeFactors(phi);
  let order = phi;

  for (const q of factors) {
    while (order % q === 0 && modPow(g, order / q, p) === 1n) {
      order /= q;
    }
  }
  return order;
}

/**
 * Check if g is a valid generator (primitive root) modulo prime p.
 * For a prime p, a valid generator g must have multiplicative order p - 1 modulo p.
 * Mathematically: g^( (p-1) / q ) !== 1 (mod p) for every prime factor q of p - 1.
 * 
 * @param {number} g 
 * @param {number} p 
 * @returns {boolean}
 */
export function isPrimitiveRoot(g, p) {
  g = Number(g);
  p = Number(p);

  if (!isPrime(p)) return false;
  if (!Number.isInteger(g) || g < 2 || g >= p) return false;

  const phi = p - 1;
  const factors = getPrimeFactors(phi);

  for (const factor of factors) {
    if (modPow(g, phi / factor, p) === 1n) {
      return false;
    }
  }
  return true;
}

/**
 * Dynamically find all valid generators modulo prime p in range [2, p - 1]
 * 
 * @param {number} p 
 * @param {number} limit 
 * @returns {number[]}
 */
export function findGenerators(p, limit = Infinity) {
  p = Number(p);
  if (!isPrime(p) || p <= 2) return [];

  const validGens = [];
  for (let candidate = 2; candidate < p; candidate++) {
    if (isPrimitiveRoot(candidate, p)) {
      validGens.push(candidate);
      if (validGens.length >= limit) break;
    }
  }
  return validGens;
}

/**
 * Categorize all integer candidates from 2 to p - 1
 * Returns an array with valid generators placed first and labeled with order.
 * 
 * @param {number} p 
 * @returns {Array<{ value: number, isGenerator: boolean, order: number, label: string }>}
 */
export function getCandidateGenerators(p) {
  p = Number(p);
  if (!isPrime(p) || p <= 2) return [];

  const candidates = [];
  for (let candidate = 2; candidate < p; candidate++) {
    const isGen = isPrimitiveRoot(candidate, p);
    const order = getOrder(candidate, p);
    candidates.push({
      value: candidate,
      isGenerator: isGen,
      order: order,
      label: isGen 
        ? `${candidate} (Valid Generator — Order ${order})` 
        : `${candidate} (Non-Generator — Subgroup Order ${order})`
    });
  }

  // Display valid generators first, followed by subgroup candidates
  candidates.sort((a, b) => {
    if (a.isGenerator === b.isGenerator) {
      return a.value - b.value;
    }
    return a.isGenerator ? -1 : 1;
  });

  return candidates;
}

/**
 * Validate prime modulus p
 * 
 * @param {any} p 
 * @returns {{ valid: boolean, message: string }}
 */
export function validatePrimeModulus(p) {
  if (p === undefined || p === null || p === '') {
    return {
      valid: false,
      message: 'Please select or enter a prime modulus p.'
    };
  }

  const num = Number(p);
  if (!Number.isInteger(num) || num < 2 || !isPrime(num)) {
    return {
      valid: false,
      message: 'Invalid modulus: p must be prime. Please select a prime number.'
    };
  }

  return {
    valid: true,
    message: ''
  };
}

/**
 * Validate generator g for prime modulus p
 * 
 * @param {any} g 
 * @param {any} p 
 * @returns {{ valid: boolean, message: string, suggestedGenerators: number[], order: number }}
 */
export function validateGeneratorModP(g, p) {
  const pCheck = validatePrimeModulus(p);
  if (!pCheck.valid) {
    return {
      valid: false,
      message: 'Please choose a valid prime modulus p first.',
      suggestedGenerators: [],
      order: 0
    };
  }

  const numP = Number(p);
  if (g === undefined || g === null || g === '') {
    return {
      valid: false,
      message: 'Please select a generator g.',
      suggestedGenerators: findGenerators(numP),
      order: 0
    };
  }

  const numG = Number(g);
  const suggestions = findGenerators(numP);

  if (!Number.isInteger(numG) || numG < 2 || numG >= numP) {
    return {
      valid: false,
      message: 'Invalid generator for the selected prime modulus.',
      suggestedGenerators: suggestions,
      order: 0
    };
  }

  if (!isPrimitiveRoot(numG, numP)) {
    const ord = getOrder(numG, numP);
    return {
      valid: false,
      message: 'Invalid generator for the selected prime modulus.',
      suggestedGenerators: suggestions,
      order: ord
    };
  }

  return {
    valid: true,
    message: `Valid generator: order is ${numP - 1} modulo ${numP}.`,
    suggestedGenerators: suggestions,
    order: numP - 1
  };
}

/**
 * Validate private exponent range: 1 <= exponent <= p - 2
 * 
 * @param {any} exp 
 * @param {any} p 
 * @param {string} name Label of the private key (e.g., "Alice's private exponent a")
 * @returns {{ valid: boolean, message: string, min: number, max: number }}
 */
export function validateExponentRange(exp, p, name = 'Private exponent') {
  const pCheck = validatePrimeModulus(p);
  if (!pCheck.valid) {
    return {
      valid: false,
      message: 'Select a valid prime modulus p first.',
      min: 1,
      max: 1
    };
  }

  const numP = Number(p);
  const max = numP - 2;
  const min = 1;

  if (max < min) {
    return {
      valid: false,
      message: `Prime p = ${numP} is too small to have valid private exponents (requires p >= 3).`,
      min,
      max
    };
  }

  if (exp === undefined || exp === null || exp === '') {
    return {
      valid: false,
      message: `${name} is required (acceptable range: ${min} <= ${name} <= ${max}).`,
      min,
      max
    };
  }

  const numExp = Number(exp);
  if (!Number.isInteger(numExp) || numExp < min || numExp > max) {
    return {
      valid: false,
      message: `${name} must be between ${min} and ${max} (acceptable range: ${min} <= ${name} <= ${max}).`,
      min,
      max
    };
  }

  return {
    valid: true,
    message: '',
    min,
    max
  };
}

/**
 * Validate complete parameter configuration
 * 
 * @param {{ p: any, g: any, a: any, b: any, mA?: any, mB?: any, isMitm?: boolean }} params 
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
export function validateParameters(params) {
  const errors = [];
  const warnings = [];

  const pRes = validatePrimeModulus(params.p);
  if (!pRes.valid) {
    errors.push(pRes.message);
  }

  const gRes = validateGeneratorModP(params.g, params.p);
  if (!gRes.valid) {
    errors.push(gRes.message);
  }

  const aRes = validateExponentRange(params.a, params.p, "Alice's private exponent a");
  if (!aRes.valid) {
    errors.push(aRes.message);
  }

  const bRes = validateExponentRange(params.b, params.p, "Bob's private exponent b");
  if (!bRes.valid) {
    errors.push(bRes.message);
  }

  if (params.isMitm) {
    const maRes = validateExponentRange(params.mA, params.p, "Mallory's exponent m_A");
    if (!maRes.valid) {
      errors.push(maRes.message);
    }
    const mbRes = validateExponentRange(params.mB, params.p, "Mallory's exponent m_B");
    if (!mbRes.valid) {
      errors.push(mbRes.message);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings
  };
}
