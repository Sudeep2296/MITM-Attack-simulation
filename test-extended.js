import { 
  isPrime, 
  isPrimitiveRoot, 
  findGenerators, 
  getCandidateGenerators,
  validatePrimeModulus, 
  validateGeneratorModP, 
  validateExponentRange, 
  validateParameters,
  SUGGESTED_PRIMES 
} from './src/core/CryptoUtils.js';
import { DiffieHellman } from './src/core/DiffieHellman.js';
import { MITMSimulation } from './src/core/MITMSimulation.js';

console.log('=== EXTENDED TEST SUITE: Diffie-Hellman & MITM Simulator ===\n');

// 1. Multiple Prime Moduli Testing
console.log('1. Testing multiple prime moduli:');
const testPrimes = [5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 97];
for (const p of testPrimes) {
  const pVal = validatePrimeModulus(p);
  console.assert(pVal.valid === true, `Expected ${p} to be valid prime`);
  
  const gens = findGenerators(p);
  console.assert(gens.length > 0, `Expected at least one generator for prime ${p}`);
  
  // Verify every generator found has order p - 1
  for (const g of gens) {
    console.assert(isPrimitiveRoot(g, p) === true, `${g} must be valid generator for ${p}`);
  }
}
console.log(`✓ Verified ${testPrimes.length} primes and their dynamically computed generators.\n`);

// 2. Testing Non-Prime (Invalid) Moduli
console.log('2. Testing composite and invalid moduli:');
const invalidModuli = [0, 1, 4, 6, 9, 15, 21, 24, 25, 33, 49, 100];
for (const comp of invalidModuli) {
  const val = validatePrimeModulus(comp);
  console.assert(val.valid === false, `Modulus ${comp} should be invalid`);
  console.assert(val.message === 'Invalid modulus: p must be prime. Please select a prime number.',
    `Expected standard error message for p=${comp}, got: ${val.message}`);
}
console.log(`✓ Verified ${invalidModuli.length} invalid moduli trigger exact error message.\n`);

// 3. Testing Valid vs Invalid Generators for p = 23
console.log('3. Testing valid and invalid generators for p = 23:');
const validGens23 = [5, 7, 10, 11, 14, 15, 17, 19, 20, 21];
for (const g of validGens23) {
  const res = validateGeneratorModP(g, 23);
  console.assert(res.valid === true, `g=${g} must be valid for p=23`);
}

const invalidGens23 = [2, 3, 4, 6, 8, 9, 12, 13, 16, 18, 22];
for (const g of invalidGens23) {
  const res = validateGeneratorModP(g, 23);
  console.assert(res.valid === false, `g=${g} must be invalid for p=23`);
  console.assert(res.message === 'Invalid generator for the selected prime modulus.',
    `Mismatch in error message for g=${g}`);
  console.assert(res.suggestedGenerators.length === 10, `Suggestions must be provided`);
  console.assert(res.suggestedGenerators[0] === 5, `Suggestions should start with 5`);
}
console.log('✓ Validated all 21 candidates in range [2, 22] for p = 23.\n');

// 4. Testing Private Exponent Boundaries (1 <= exp <= p - 2)
console.log('4. Testing private exponent boundaries:');
const p = 23;
// Valid boundaries
console.assert(validateExponentRange(1, p, 'a').valid === true, 'a = 1 is lower boundary (valid)');
console.assert(validateExponentRange(21, p, 'a').valid === true, 'a = p - 2 = 21 is upper boundary (valid)');
console.assert(validateExponentRange(10, p, 'a').valid === true, 'a = 10 is interior value (valid)');

// Invalid boundaries
console.assert(validateExponentRange(0, p, 'a').valid === false, 'a = 0 is below boundary (invalid)');
console.assert(validateExponentRange(22, p, 'a').valid === false, 'a = p - 1 = 22 is above boundary (invalid)');
console.assert(validateExponentRange(23, p, 'a').valid === false, 'a = p = 23 is above boundary (invalid)');
console.assert(validateExponentRange(-5, p, 'a').valid === false, 'a = -5 is negative (invalid)');
console.log('✓ Boundary tests (1 <= exp <= p - 2) passed.\n');

// 5. Diffie-Hellman Key Exchange across multiple parameter sets
console.log('5. Testing Diffie-Hellman across diverse parameter sets:');
const testCases = [
  { p: 7, g: 3, a: 2, b: 4 },
  { p: 13, g: 2, a: 3, b: 7 },
  { p: 17, g: 3, a: 5, b: 9 },
  { p: 23, g: 5, a: 6, b: 15 },
  { p: 47, g: 5, a: 11, b: 18 },
  { p: 97, g: 5, a: 24, b: 36 }
];

for (const tc of testCases) {
  const sim = new DiffieHellman(tc.p, tc.g, tc.a, tc.b);
  console.assert(sim.isMatch === true, `Shared secret must match for p=${tc.p}`);
  console.assert(sim.Ka === sim.Kb, `Ka (${sim.Ka}) must equal Kb (${sim.Kb})`);
  console.log(`  p=${tc.p}, g=${tc.g}, a=${tc.a}, b=${tc.b} => A=${sim.A}, B=${sim.B}, Shared Key K=${sim.Ka}`);
}
console.log('✓ All DH key agreements verified identical secrets.\n');

// 6. MITM Attack Simulation across diverse parameter sets
console.log('6. Testing MITM Attack Simulation:');
for (const tc of testCases) {
  const mA = 3;
  const mB = 4;
  const mitm = new MITMSimulation(tc.p, tc.g, tc.a, tc.b, mA, mB);
  
  console.assert(mitm.KaAlice === mitm.KaMallory, `Alice-Mallory secret must match`);
  console.assert(mitm.KbBob === mitm.KbMallory, `Bob-Mallory secret must match`);
  console.log(`  p=${tc.p} MITM: Ka_Alice=${mitm.KaAlice}, Kb_Bob=${mitm.KbBob} (Split: ${mitm.secretsAreSplit})`);
}
console.log('✓ MITM attack simulation verified on all test cases.\n');

console.log('ALL EXTENDED TESTS COMPLETED SUCCESSFULLY! 🚀');
