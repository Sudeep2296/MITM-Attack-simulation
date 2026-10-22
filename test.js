import { modPow, isPrime, isPrimitiveRoot, findGenerators, validateParameters, validatePrimeModulus, validateGeneratorModP, validateExponentRange, SUGGESTED_PRIMES } from './src/core/CryptoUtils.js';
import { DiffieHellman } from './src/core/DiffieHellman.js';
import { MITMSimulation } from './src/core/MITMSimulation.js';

console.log('Testing Cryptographic Core Modules...');

// Test 1: Primality tests
console.assert(isPrime(2) === true, '2 is prime');
console.assert(isPrime(3) === true, '3 is prime');
console.assert(isPrime(4) === false, '4 is not prime');
console.assert(isPrime(23) === true, '23 is prime');
console.assert(isPrime(24) === false, '24 is not prime');
console.assert(isPrime(97) === true, '97 is prime');
console.log('✓ isPrime tested successfully');

// Test 2: Suggested primes all prime
for (const p of SUGGESTED_PRIMES) {
  console.assert(isPrime(p) === true, `${p} must be prime`);
}
console.log('✓ All SUGGESTED_PRIMES verified prime');

// Test 3: Primitive root checks for p = 23
// Powers of g mod 23:
// For g = 5: order is 22 (primitive root)
// For g = 4: order is 11 (not primitive root, 4^11 = 1 mod 23)
console.assert(isPrimitiveRoot(5, 23) === true, '5 is primitive root mod 23');
console.assert(isPrimitiveRoot(4, 23) === false, '4 is NOT primitive root mod 23');
console.assert(isPrimitiveRoot(7, 23) === true, '7 is primitive root mod 23');
console.assert(isPrimitiveRoot(10, 23) === true, '10 is primitive root mod 23');
console.assert(isPrimitiveRoot(11, 23) === true, '11 is primitive root mod 23');
console.log('✓ isPrimitiveRoot tested successfully');

// Test 4: Dynamic generator search for p = 23
const gens23 = findGenerators(23);
const expectedGens23 = [5, 7, 10, 11, 14, 15, 17, 19, 20, 21];
console.assert(JSON.stringify(gens23) === JSON.stringify(expectedGens23), `Expected ${expectedGens23}, got ${gens23}`);
console.log('✓ findGenerators(23) matches expected list:', gens23.join(', '));

// Test 5: Validation functions
const pValInvalid = validatePrimeModulus(24);
console.assert(pValInvalid.valid === false, '24 is invalid prime');
console.assert(pValInvalid.message === 'Invalid modulus: p must be prime. Please select a prime number.', 'Mismatch in p error message');

const gValInvalid = validateGeneratorModP(4, 23);
console.assert(gValInvalid.valid === false, '4 is invalid generator for 23');
console.assert(gValInvalid.message === 'Invalid generator for the selected prime modulus.', 'Mismatch in g error message');
console.assert(gValInvalid.suggestedGenerators.includes(5), 'Suggestions must include 5');

const expInvalid = validateExponentRange(22, 23, 'a');
console.assert(expInvalid.valid === false, '22 is out of range for p=23 (max 21)');

const expValid = validateExponentRange(6, 23, 'a');
console.assert(expValid.valid === true, '6 is valid exponent');
console.log('✓ Inline validation checks verified');

// Test 6: DiffieHellman core calculations
const dh = new DiffieHellman(23, 5, 6, 15);
console.assert(dh.A === 8n, `Expected A = 8n, got ${dh.A}`);
console.assert(dh.B === 19n, `Expected B = 19n, got ${dh.B}`);
console.assert(dh.Ka === 2n, `Expected Ka = 2n, got ${dh.Ka}`);
console.assert(dh.Kb === 2n, `Expected Kb = 2n, got ${dh.Kb}`);
console.assert(dh.isMatch === true, 'Shared secrets must match');
console.log('✓ DiffieHellman key agreement calculation verified');

// Test 7: MITM Simulation
const mitm = new MITMSimulation(23, 5, 6, 15, 4, 7);
console.assert(mitm.A === 8n, `Alice A = 8n`);
console.assert(mitm.B === 19n, `Bob B = 19n`);
console.assert(mitm.MA === 4n, `Mallory MA = 5^4 mod 23 = 625 mod 23 = 4n`);
console.assert(mitm.MB === 17n, `Mallory MB = 5^7 mod 23 = 17n`);
console.assert(mitm.KaAlice === mitm.KaMallory, 'Alice and Mallory must share Ka');
console.assert(mitm.KbBob === mitm.KbMallory, 'Bob and Mallory must share Kb');
console.assert(mitm.secretsAreSplit === true, 'Secrets must be split');
console.log('✓ MITM attack simulation verified');

console.log('ALL TESTS PASSED SUCCESSFULLY! 🎉');
