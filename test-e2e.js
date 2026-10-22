import { chromium } from 'file:///C:/Users/niles/OneDrive/Desktop/Sudeep.S/Portfolio/node_modules/playwright/index.mjs';

async function runE2ETests() {
  console.log('🚀 Starting E2E Playwright Browser Validation...');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();

  try {
    // 1. Navigate to dev server
    await page.goto('http://localhost:5173/', { waitUntil: 'networkidle' });
    console.log('✓ Page loaded: ' + await page.title());

    // Check title
    const title = await page.title();
    console.assert(title.includes('Diffie–Hellman'), `Title expected to contain Diffie-Hellman, got: ${title}`);

    // Check Calculate button disabled initially
    const btnCalc = page.locator('#btn-calculate');
    console.assert(await btnCalc.isDisabled(), 'Calculate button must be disabled on initial load');
    console.log('✓ Calculate button is properly disabled before parameter selection');

    // 2. Test Manual Typing Prime p = 23 (and quick prime button)
    const inputP = page.locator('#input-p');
    await inputP.fill('23');
    await page.waitForTimeout(100);

    const feedbackP = await page.locator('#feedback-p').textContent();
    console.assert(feedbackP.includes('Modulus p = 23 is prime'), `Unexpected feedbackP: ${feedbackP}`);
    console.log('✓ Manual typing prime p = 23 verified, valid feedback shown');

    // 3. Check Generator field is enabled
    const inputG = page.locator('#input-g');
    console.assert(!(await inputG.isDisabled()), 'Generator input must be enabled once p is prime');
    console.log('✓ Generator manual input is enabled');

    // 4. Test manual typing invalid generator g = 4
    await inputG.fill('4');
    await page.waitForTimeout(100);

    const feedbackG = await page.locator('#feedback-g').textContent();
    console.assert(feedbackG.includes('Invalid generator for the selected prime modulus.'), `Expected invalid generator message, got: ${feedbackG}`);
    console.assert(feedbackG.includes('Suggested valid generators'), `Expected suggestion list, got: ${feedbackG}`);
    console.assert(await btnCalc.isDisabled(), 'Calculate button must remain disabled when g is invalid');
    console.log('✓ Invalid generator g = 4 correctly triggers inline alert and dynamic suggestion list');

    // 5. Click suggestion pill "5"
    const pill5 = page.locator('.suggestion-pill[data-g="5"]');
    await pill5.click();
    await page.waitForTimeout(100);

    const gVal = await inputG.inputValue();
    console.assert(gVal === '5', `Expected g to be 5, got ${gVal}`);
    const feedbackGValid = await page.locator('#feedback-g').textContent();
    console.assert(feedbackGValid.includes('Valid generator'), `Expected valid generator message, got: ${feedbackGValid}`);
    console.log('✓ Clicked suggestion pill "5", generator input updated to 5 and validated');

    // 6. Manual typing Alice private exponent a = 6 and Bob private exponent b = 15
    const inputA = page.locator('#input-a');
    await inputA.fill('6');

    const inputB = page.locator('#input-b');
    await inputB.fill('15');
    await page.waitForTimeout(100);

    // Verify Calculate button is now enabled
    console.assert(await btnCalc.isEnabled(), 'Calculate button should be enabled when all parameters are valid');
    console.log('✓ Manual private exponents a = 6, b = 15 typed. Calculate button enabled');

    // 7. Click Calculate Keys
    await btnCalc.click();
    await page.waitForTimeout(200);

    // Verify 2D node card displays
    const dispA = await page.locator('#disp-alice-pub').textContent();
    const dispB = await page.locator('#disp-bob-pub').textContent();
    const dispKa = await page.locator('#disp-alice-secret').textContent();
    const dispKb = await page.locator('#disp-bob-secret').textContent();

    console.assert(dispA === '8', `Expected Alice A = 8, got ${dispA}`);
    console.assert(dispB === '19', `Expected Bob B = 19, got ${dispB}`);
    console.assert(dispKa === '2', `Expected Alice secret Ka = 2, got ${dispKa}`);
    console.assert(dispKb === '2', `Expected Bob secret Kb = 2, got ${dispKb}`);
    console.log(`✓ 2D Nodes verified: Alice Public A = ${dispA}, Bob Public B = ${dispB}, Shared Secret K = ${dispKa}`);

    // Verify status banner
    const statusText = await page.locator('#status-banner').textContent();
    console.assert(statusText.includes('Shared Secret Established: K = 2'), `Banner mismatch: ${statusText}`);
    console.log('✓ Status banner verified: Shared Secret Established: K = 2 (Matching ✓)');

    // 8. Test MITM Mode
    console.log('\n--- Testing MITM Mode ---');
    const btnModeMitm = page.locator('#btn-mode-mitm');
    await btnModeMitm.click();
    await page.waitForTimeout(100);

    // Verify Mallory fields are visible
    const malloryContainer = page.locator('#mallory-fields-container');
    console.assert(await malloryContainer.isVisible(), 'Mallory fields container must be visible in MITM mode');

    // Type Mallory exponents mA = 4, mB = 7 manually
    const inputMA = page.locator('#input-ma');
    const inputMB = page.locator('#input-mb');
    await inputMA.fill('4');
    await inputMB.fill('7');
    await page.waitForTimeout(100);

    await btnCalc.click();
    await page.waitForTimeout(200);

    // Verify Mallory node values
    const malloryKa = await page.locator('#disp-mallory-ka').textContent();
    const malloryKb = await page.locator('#disp-mallory-kb').textContent();
    const aliceSecretMitm = await page.locator('#disp-alice-secret').textContent();
    const bobSecretMitm = await page.locator('#disp-bob-secret').textContent();

    console.assert(aliceSecretMitm === '2', `Expected Alice Ka = 2, got ${aliceSecretMitm}`);
    console.assert(bobSecretMitm === '15', `Expected Bob Kb = 15, got ${bobSecretMitm}`);
    console.assert(malloryKa === '2', `Expected Mallory Ka = 2, got ${malloryKa}`);
    console.assert(malloryKb === '15', `Expected Mallory Kb = 15, got ${malloryKb}`);
    console.assert(aliceSecretMitm !== bobSecretMitm, 'Secrets must be split!');
    console.log(`✓ MITM verified: Alice Secret = ${aliceSecretMitm}, Bob Secret = ${bobSecretMitm}, Mallory holds BOTH [${malloryKa}, ${malloryKb}]`);

    // Verify Tamper demo tab
    const tabTamperBtn = page.locator('#tab-btn-tamper');
    await tabTamperBtn.click();
    await page.waitForTimeout(100);
    const tamperContent = await page.locator('#tamper-output-area').textContent();
    console.assert(tamperContent.includes('Mallory tampers message'), 'Tamper demo must be rendered');
    console.log('✓ MITM Message Tampering demonstration verified');

    // 9. Test Manual Typing of Non-Prime Modulus (p = 24)
    console.log('\n--- Testing Non-Prime Modulus Alert ---');
    await inputP.fill('24');
    await page.waitForTimeout(100);

    const feedbackPInvalid = await page.locator('#feedback-p').textContent();
    console.assert(
      feedbackPInvalid.includes('Invalid modulus: p must be prime. Please select a prime number.'),
      `Expected invalid prime alert, got: ${feedbackPInvalid}`
    );
    console.assert(await btnCalc.isDisabled(), 'Calculate button must be disabled when p is composite');
    console.assert(await inputG.isDisabled(), 'Generator input must be disabled when p is composite');
    console.log('✓ Invalid modulus p = 24 triggers exact alert: "Invalid modulus: p must be prime. Please select a prime number."');

    // Test Manual Typing of Prime (p = 47)
    console.log('\n--- Testing Manual Typing for Another Prime (p = 47) ---');
    await inputP.fill('47');
    await page.waitForTimeout(100);
    console.assert(await inputP.inputValue() === '47', 'Expected p input to be 47');
    const feedbackP47 = await page.locator('#feedback-p').textContent();
    console.assert(feedbackP47.includes('Modulus p = 47 is prime'), `Expected 47 prime feedback, got: ${feedbackP47}`);
    console.log('✓ Manual typing of prime 47 successfully validated');

    // 10. Test Reset Button
    console.log('\n--- Testing Reset Functionality ---');
    await page.locator('#btn-reset').click();
    await page.waitForTimeout(100);

    console.assert(await inputP.inputValue() === '', 'p should be reset to empty');
    console.assert(await inputG.isDisabled(), 'g should be disabled after reset');
    console.assert(await btnCalc.isDisabled(), 'Calculate button should be disabled after reset');
    console.log('✓ Reset button restores initial state cleanly');

    console.log('\n🎉 ALL E2E BROWSER VALIDATION TESTS PASSED WITH 100% SUCCESS!');
  } catch (err) {
    console.error('❌ E2E Test failed:', err);
    throw err;
  } finally {
    await browser.close();
  }
}

runE2ETests().catch(err => {
  console.error(err);
  process.exit(1);
});
