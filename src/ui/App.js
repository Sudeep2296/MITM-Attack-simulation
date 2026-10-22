import { 
  isPrime, 
  isPrimitiveRoot, 
  findGenerators, 
  getCandidateGenerators,
  getOrder,
  validatePrimeModulus, 
  validateGeneratorModP, 
  validateExponentRange, 
  modPow,
  SUGGESTED_PRIMES 
} from '../core/CryptoUtils.js';
import { DiffieHellman } from '../core/DiffieHellman.js';
import { MITMSimulation } from '../core/MITMSimulation.js';

export class App {
  constructor() {
    this.mode = 'normal'; // 'normal' | 'mitm'
    this.currentP = null;
    this.currentG = null;
    this.currentA = null;
    this.currentB = null;
    this.currentMA = null;
    this.currentMB = null;
    this.calculatedDH = null;
    this.calculatedMITM = null;

    // Granular step-by-step interactive state
    this.stepState = {
      alicePub: null,
      bobPub: null,
      aliceReceived: null,
      bobReceived: null,
      aliceSecret: null,
      bobSecret: null,
      malloryKa: null,
      malloryKb: null,
    };

    this.initElements();
    this.attachEvents();
    this.revalidateAll();
  }

  initElements() {
    // Mode toggles
    this.btnModeNormal = document.getElementById('btn-mode-normal');
    this.btnModeMitm = document.getElementById('btn-mode-mitm');
    this.radioModeNormal = document.getElementById('radio-mode-normal');
    this.radioModeMitm = document.getElementById('radio-mode-mitm');

    // Controls
    this.btnCalculate = document.getElementById('btn-calculate');
    this.btnReset = document.getElementById('btn-reset');
    this.btnLoadExample = document.getElementById('btn-load-example');

    // Public Parameters (Manual Typing)
    this.inputP = document.getElementById('input-p');
    this.feedbackP = document.getElementById('feedback-p');

    this.inputG = document.getElementById('input-g');
    this.feedbackG = document.getElementById('feedback-g');

    // Private Parameters (Manual Typing)
    this.inputA = document.getElementById('input-a');
    this.feedbackA = document.getElementById('feedback-a');

    this.inputB = document.getElementById('input-b');
    this.feedbackB = document.getElementById('feedback-b');

    // Mallory Parameters (MITM Mode - Manual Typing)
    this.malloryFieldsContainer = document.getElementById('mallory-fields-container');
    this.inputMA = document.getElementById('input-ma');
    this.feedbackMA = document.getElementById('feedback-ma');

    this.inputMB = document.getElementById('input-mb');
    this.feedbackMB = document.getElementById('feedback-mb');

    // Step Action Buttons & In-Card Elements
    this.btnGenerateP = document.getElementById('btn-generate-p');
    this.btnGenerateG = document.getElementById('btn-generate-g');
    this.btnGenerateA = document.getElementById('btn-generate-a');
    this.btnGenerateB = document.getElementById('btn-generate-b');
    this.btnGenerateMA = document.getElementById('btn-generate-ma');
    this.btnGenerateMB = document.getElementById('btn-generate-mb');

    this.btnCalcAlicePub = document.getElementById('btn-calc-alice-pub');
    this.btnCalcBobPub = document.getElementById('btn-calc-bob-pub');
    this.btnSendAlice = document.getElementById('btn-send-alice');
    this.btnSendBob = document.getElementById('btn-send-bob');
    this.btnCalcAliceSecret = document.getElementById('btn-calc-alice-secret');
    this.btnCalcBobSecret = document.getElementById('btn-calc-bob-secret');

    this.displayAliceReceived = document.getElementById('disp-alice-received');
    this.displayBobReceived = document.getElementById('disp-bob-received');

    // 2D Protocol Flow Diagram
    this.networkFlow = document.getElementById('network-flow');
    this.nodeAlice = document.getElementById('node-alice');
    this.nodeMallory = document.getElementById('node-mallory');
    this.nodeBob = document.getElementById('node-bob');

    this.wireNormal = document.getElementById('wire-normal');
    this.wireMitmLeft = document.getElementById('wire-mitm-left');
    this.wireMitmRight = document.getElementById('wire-mitm-right');

    // Node Metrics Display
    this.displayAlicePriv = document.getElementById('disp-alice-priv');
    this.displayAlicePub = document.getElementById('disp-alice-pub');
    this.displayAliceSecret = document.getElementById('disp-alice-secret');

    this.displayBobPriv = document.getElementById('disp-bob-priv');
    this.displayBobPub = document.getElementById('disp-bob-pub');
    this.displayBobSecret = document.getElementById('disp-bob-secret');

    this.displayMalloryMapriv = document.getElementById('disp-mallory-mapriv');
    this.displayMalloryMbpriv = document.getElementById('disp-mallory-mbpriv');
    this.displayMalloryMa = document.getElementById('disp-mallory-ma');
    this.displayMalloryMb = document.getElementById('disp-mallory-mb');
    this.displayMalloryKa = document.getElementById('disp-mallory-ka');
    this.displayMalloryKb = document.getElementById('disp-mallory-kb');

    // Results & Viva
    this.statusBanner = document.getElementById('status-banner');
    this.resultsFormulas = document.getElementById('results-formulas');
    this.tabTamperContainer = document.getElementById('tab-pane-tamper');
    this.tabTamperBtn = document.getElementById('tab-btn-tamper');
    this.tamperInputMsg = document.getElementById('tamper-msg-input');
    this.tamperOutputArea = document.getElementById('tamper-output-area');
  }

  attachEvents() {
    // Mode Switching
    this.btnModeNormal.addEventListener('click', () => this.setMode('normal'));
    this.btnModeMitm.addEventListener('click', () => this.setMode('mitm'));

    // Actions
    this.btnCalculate.addEventListener('click', () => this.handleCalculate());
    this.btnReset.addEventListener('click', () => this.handleReset());
    this.btnLoadExample.addEventListener('click', () => this.loadSuggestedExample());

    // Step Generators
    if (this.btnGenerateP) {
      this.btnGenerateP.addEventListener('click', () => this.generateRandomPrime());
    }
    if (this.btnGenerateG) {
      this.btnGenerateG.addEventListener('click', () => this.generateRandomGenerator());
    }
    if (this.btnGenerateA) {
      this.btnGenerateA.addEventListener('click', () => this.generateRandomExponentA());
    }
    if (this.btnGenerateB) {
      this.btnGenerateB.addEventListener('click', () => this.generateRandomExponentB());
    }
    if (this.btnGenerateMA) {
      this.btnGenerateMA.addEventListener('click', () => this.generateRandomExponentMA());
    }
    if (this.btnGenerateMB) {
      this.btnGenerateMB.addEventListener('click', () => this.generateRandomExponentMB());
    }

    // Step Action Buttons (Individual step execution)
    if (this.btnCalcAlicePub) {
      this.btnCalcAlicePub.addEventListener('click', () => this.handleCalcAlicePub());
    }
    if (this.btnCalcBobPub) {
      this.btnCalcBobPub.addEventListener('click', () => this.handleCalcBobPub());
    }
    if (this.btnSendAlice) {
      this.btnSendAlice.addEventListener('click', () => this.handleSendAlice());
    }
    if (this.btnSendBob) {
      this.btnSendBob.addEventListener('click', () => this.handleSendBob());
    }
    if (this.btnCalcAliceSecret) {
      this.btnCalcAliceSecret.addEventListener('click', () => this.handleCalcAliceSecret());
    }
    if (this.btnCalcBobSecret) {
      this.btnCalcBobSecret.addEventListener('click', () => this.handleCalcBobSecret());
    }

    // Public inputs (Manual Typing)
    if (this.inputP) {
      this.inputP.addEventListener('input', () => this.handlePChange());
    }

    if (this.inputG) {
      this.inputG.addEventListener('input', () => this.handleGChange());
    }

    // Private inputs (Manual Typing)
    if (this.inputA) {
      this.inputA.addEventListener('input', () => this.handleAChange());
    }

    if (this.inputB) {
      this.inputB.addEventListener('input', () => this.handleBChange());
    }

    // Mallory inputs (Manual Typing)
    if (this.inputMA) {
      this.inputMA.addEventListener('input', () => this.handleMAChange());
    }

    if (this.inputMB) {
      this.inputMB.addEventListener('input', () => this.handleMBChange());
    }

    // Tamper message demo
    if (this.tamperInputMsg) {
      this.tamperInputMsg.addEventListener('input', () => this.updateTamperDemo());
    }

    // Tab buttons
    document.querySelectorAll('.tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tabKey = e.currentTarget.getAttribute('data-tab');
        this.switchTab(tabKey);
      });
    });
  }

  switchTab(tabKey) {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

    const btn = document.querySelector(`.tab-btn[data-tab="${tabKey}"]`);
    const pane = document.getElementById(`tab-pane-${tabKey}`);
    if (btn) btn.classList.add('active');
    if (pane) pane.classList.add('active');
  }

  setMode(newMode) {
    this.mode = newMode;
    const isMitm = (newMode === 'mitm');

    this.btnModeNormal.classList.toggle('active', !isMitm);
    this.btnModeMitm.classList.toggle('active', isMitm);
    if (this.radioModeNormal) this.radioModeNormal.checked = !isMitm;
    if (this.radioModeMitm) this.radioModeMitm.checked = isMitm;

    // Toggle Mallory input parameters
    this.malloryFieldsContainer.style.display = isMitm ? 'flex' : 'none';

    // Toggle 2D diagram layout
    this.networkFlow.classList.toggle('mitm-active', isMitm);
    this.nodeMallory.style.display = isMitm ? 'flex' : 'none';
    this.wireNormal.style.display = isMitm ? 'none' : 'flex';
    this.wireMitmLeft.style.display = isMitm ? 'flex' : 'none';
    this.wireMitmRight.style.display = isMitm ? 'flex' : 'none';

    // Toggle Tampering Tab button
    if (this.tabTamperBtn) {
      this.tabTamperBtn.style.display = isMitm ? 'block' : 'none';
    }

    this.revalidateAll();

    // Re-calculate if already valid
    if (this.btnCalculate && !this.btnCalculate.disabled) {
      this.handleCalculate();
    }
  }

  getPValue() {
    if (!this.inputP) return null;
    const v = this.inputP.value.trim();
    return v === '' ? null : Number(v);
  }

  getGValue() {
    if (!this.inputG) return null;
    const v = this.inputG.value.trim();
    return v === '' ? null : Number(v);
  }

  getAValue() {
    if (!this.inputA) return null;
    const v = this.inputA.value.trim();
    return v === '' ? null : Number(v);
  }

  getBValue() {
    if (!this.inputB) return null;
    const v = this.inputB.value.trim();
    return v === '' ? null : Number(v);
  }

  getMAValue() {
    if (!this.inputMA) return null;
    const v = this.inputMA.value.trim();
    return v === '' ? null : Number(v);
  }

  getMBValue() {
    if (!this.inputMB) return null;
    const v = this.inputMB.value.trim();
    return v === '' ? null : Number(v);
  }

  handlePChange() {
    const p = this.getPValue();
    this.currentP = p;

    const isPValid = (p !== null && isPrime(p));

    // Enable/disable subsequent fields
    if (this.inputG) {
      this.inputG.disabled = !isPValid;
      this.inputG.placeholder = isPValid ? 'e.g. 5' : 'set p first';
    }

    if (this.inputA) {
      this.inputA.disabled = !isPValid;
      this.inputA.placeholder = isPValid ? 'e.g. 6' : 'set p first';
    }

    if (this.inputB) {
      this.inputB.disabled = !isPValid;
      this.inputB.placeholder = isPValid ? 'e.g. 15' : 'set p first';
    }

    if (this.inputMA) {
      this.inputMA.disabled = !isPValid;
      this.inputMA.placeholder = isPValid ? 'e.g. 4' : 'set p first';
    }

    if (this.inputMB) {
      this.inputMB.disabled = !isPValid;
      this.inputMB.placeholder = isPValid ? 'e.g. 7' : 'set p first';
    }

    // Enable/disable helper generator buttons
    if (this.btnGenerateG) this.btnGenerateG.disabled = !isPValid;
    if (this.btnGenerateA) this.btnGenerateA.disabled = !isPValid;
    if (this.btnGenerateB) this.btnGenerateB.disabled = !isPValid;
    if (this.btnGenerateMA) this.btnGenerateMA.disabled = !isPValid;
    if (this.btnGenerateMB) this.btnGenerateMB.disabled = !isPValid;

    this.resetStepCalculations();
    this.revalidateAll();
  }

  handleGChange() {
    this.currentG = this.getGValue();
    this.resetStepCalculations();
    this.revalidateAll();
  }

  handleAChange() {
    this.currentA = this.getAValue();
    this.stepState.alicePub = null;
    this.stepState.aliceSecret = null;
    if (this.displayAlicePub) this.displayAlicePub.textContent = '—';
    if (this.displayAliceSecret) {
      this.displayAliceSecret.textContent = '—';
      this.displayAliceSecret.className = 'metric-display-box metric-value';
    }
    if (this.mode === 'normal') {
      this.stepState.bobReceived = null;
      this.stepState.bobSecret = null;
      if (this.displayBobReceived) this.displayBobReceived.textContent = '—';
      if (this.displayBobSecret) {
        this.displayBobSecret.textContent = '—';
        this.displayBobSecret.className = 'metric-display-box metric-value';
      }
      const wireA = document.getElementById('wire-tag-a');
      if (wireA) wireA.textContent = 'A →';
    }
    this.revalidateAll();
  }

  handleBChange() {
    this.currentB = this.getBValue();
    this.stepState.bobPub = null;
    this.stepState.bobSecret = null;
    if (this.displayBobPub) this.displayBobPub.textContent = '—';
    if (this.displayBobSecret) {
      this.displayBobSecret.textContent = '—';
      this.displayBobSecret.className = 'metric-display-box metric-value';
    }
    if (this.mode === 'normal') {
      this.stepState.aliceReceived = null;
      this.stepState.aliceSecret = null;
      if (this.displayAliceReceived) this.displayAliceReceived.textContent = '—';
      if (this.displayAliceSecret) {
        this.displayAliceSecret.textContent = '—';
        this.displayAliceSecret.className = 'metric-display-box metric-value';
      }
      const wireB = document.getElementById('wire-tag-b');
      if (wireB) wireB.textContent = '← B';
    }
    this.revalidateAll();
  }

  handleMAChange() {
    this.currentMA = this.getMAValue();
    this.stepState.malloryKa = null;
    this.stepState.aliceReceived = null;
    this.stepState.aliceSecret = null;
    if (this.displayMalloryKa) this.displayMalloryKa.textContent = '—';
    if (this.displayAliceReceived) this.displayAliceReceived.textContent = '—';
    if (this.displayAliceSecret) {
      this.displayAliceSecret.textContent = '—';
      this.displayAliceSecret.className = 'metric-display-box metric-value';
    }
    this.revalidateAll();
  }

  handleMBChange() {
    this.currentMB = this.getMBValue();
    this.stepState.malloryKb = null;
    this.stepState.bobReceived = null;
    this.stepState.bobSecret = null;
    if (this.displayMalloryKb) this.displayMalloryKb.textContent = '—';
    if (this.displayBobReceived) this.displayBobReceived.textContent = '—';
    if (this.displayBobSecret) {
      this.displayBobSecret.textContent = '—';
      this.displayBobSecret.className = 'metric-display-box metric-value';
    }
    this.revalidateAll();
  }

  generateRandomPrime() {
    const primes = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 71, 79, 83, 89, 97];
    const current = this.getPValue();
    const filtered = primes.filter(p => p !== current);
    const chosen = filtered[Math.floor(Math.random() * filtered.length)];
    if (this.inputP) {
      this.inputP.value = chosen.toString();
      this.handlePChange();
    }
  }

  generateRandomGenerator() {
    const p = this.getPValue();
    if (!p || !isPrime(p)) return;
    const gens = findGenerators(p);
    if (!gens || gens.length === 0) return;
    const current = this.getGValue();
    const filtered = gens.filter(g => g !== current);
    const chosen = filtered.length > 0 
      ? filtered[Math.floor(Math.random() * filtered.length)]
      : gens[0];
    if (this.inputG) {
      this.inputG.value = chosen.toString();
      this.handleGChange();
    }
  }

  generateRandomExponentA() {
    const p = this.getPValue();
    if (!p || !isPrime(p) || p <= 2) return;
    const max = p - 2;
    const val = Math.floor(Math.random() * max) + 1;
    if (this.inputA) {
      this.inputA.value = val.toString();
      this.handleAChange();
    }
  }

  generateRandomExponentB() {
    const p = this.getPValue();
    if (!p || !isPrime(p) || p <= 2) return;
    const max = p - 2;
    const val = Math.floor(Math.random() * max) + 1;
    if (this.inputB) {
      this.inputB.value = val.toString();
      this.handleBChange();
    }
  }

  generateRandomExponentMA() {
    const p = this.getPValue();
    if (!p || !isPrime(p) || p <= 2) return;
    const max = p - 2;
    const val = Math.floor(Math.random() * max) + 1;
    if (this.inputMA) {
      this.inputMA.value = val.toString();
      this.handleMAChange();
    }
  }

  generateRandomExponentMB() {
    const p = this.getPValue();
    if (!p || !isPrime(p) || p <= 2) return;
    const max = p - 2;
    const val = Math.floor(Math.random() * max) + 1;
    if (this.inputMB) {
      this.inputMB.value = val.toString();
      this.handleMBChange();
    }
  }

  resetStepCalculations() {
    this.stepState = {
      alicePub: null,
      bobPub: null,
      aliceReceived: null,
      bobReceived: null,
      aliceSecret: null,
      bobSecret: null,
      malloryKa: null,
      malloryKb: null,
    };
    if (this.displayAlicePub) this.displayAlicePub.textContent = '—';
    if (this.displayBobPub) this.displayBobPub.textContent = '—';
    if (this.displayAliceReceived) this.displayAliceReceived.textContent = '—';
    if (this.displayBobReceived) this.displayBobReceived.textContent = '—';
    if (this.displayAliceSecret) {
      this.displayAliceSecret.textContent = '—';
      this.displayAliceSecret.className = 'metric-display-box metric-value';
    }
    if (this.displayBobSecret) {
      this.displayBobSecret.textContent = '—';
      this.displayBobSecret.className = 'metric-display-box metric-value';
    }
    if (this.displayMalloryKa) this.displayMalloryKa.textContent = '—';
    if (this.displayMalloryKb) this.displayMalloryKb.textContent = '—';

    const wireA = document.getElementById('wire-tag-a');
    const wireB = document.getElementById('wire-tag-b');
    if (wireA) wireA.textContent = 'A →';
    if (wireB) wireB.textContent = '← B';

    const tagAIntercept = document.getElementById('tag-a-intercept');
    const tagMaSpoof = document.getElementById('tag-ma-spoof');
    const tagBIntercept = document.getElementById('tag-b-intercept');
    const tagMbSpoof = document.getElementById('tag-mb-spoof');
    if (tagAIntercept) tagAIntercept.textContent = 'A → (Intercepted)';
    if (tagMaSpoof) tagMaSpoof.textContent = '← Fake M_A';
    if (tagMbSpoof) tagMbSpoof.textContent = 'Fake M_B →';
    if (tagBIntercept) tagBIntercept.textContent = '← B (Intercepted)';

    if (this.btnSendAlice) this.btnSendAlice.disabled = true;
    if (this.btnSendBob) this.btnSendBob.disabled = true;
    if (this.btnCalcAliceSecret) this.btnCalcAliceSecret.disabled = true;
    if (this.btnCalcBobSecret) this.btnCalcBobSecret.disabled = true;
  }

  handleCalcAlicePub() {
    const p = this.getPValue();
    const g = this.getGValue();
    const a = this.getAValue();

    if (!p || !isPrime(p) || !g || !isPrimitiveRoot(g, p) || !a || !validateExponentRange(a, p).valid) {
      return;
    }

    const A = modPow(g, a, p);
    this.stepState.alicePub = A;
    if (this.displayAlicePub) this.displayAlicePub.textContent = A.toString();
    this.revalidateAll();
  }

  handleCalcBobPub() {
    const p = this.getPValue();
    const g = this.getGValue();
    const b = this.getBValue();

    if (!p || !isPrime(p) || !g || !isPrimitiveRoot(g, p) || !b || !validateExponentRange(b, p).valid) {
      return;
    }

    const B = modPow(g, b, p);
    this.stepState.bobPub = B;
    if (this.displayBobPub) this.displayBobPub.textContent = B.toString();
    this.revalidateAll();
  }

  handleSendAlice() {
    if (this.stepState.alicePub === null) return;
    const p = this.getPValue();
    const g = this.getGValue();
    const b = this.getBValue();

    if (this.mode === 'normal') {
      const wireA = document.getElementById('wire-tag-a');
      if (wireA) wireA.textContent = `A = ${this.stepState.alicePub} →`;

      this.stepState.bobReceived = this.stepState.alicePub;
      if (this.displayBobReceived) {
        this.displayBobReceived.textContent = this.stepState.alicePub.toString();
      }

      if (b !== null && validateExponentRange(b, p).valid && this.btnCalcBobSecret) {
        this.btnCalcBobSecret.disabled = false;
      }
    } else {
      const tagAIntercept = document.getElementById('tag-a-intercept');
      if (tagAIntercept) tagAIntercept.textContent = `A = ${this.stepState.alicePub} (Intercepted)`;

      const mA = this.getMAValue();
      const mB = this.getMBValue();

      if (mA !== null && validateExponentRange(mA, p).valid) {
        const KaM = modPow(this.stepState.alicePub, mA, p);
        this.stepState.malloryKa = KaM;
        if (this.displayMalloryKa) {
          this.displayMalloryKa.textContent = KaM.toString();
          this.displayMalloryKa.className = 'metric-display-box secret-compromise';
        }
      }

      if (mB !== null && validateExponentRange(mB, p).valid) {
        const MB = modPow(g, mB, p);
        const tagMbSpoof = document.getElementById('tag-mb-spoof');
        if (tagMbSpoof) tagMbSpoof.textContent = `Fake M_B = ${MB} →`;

        this.stepState.bobReceived = MB;
        if (this.displayBobReceived) {
          this.displayBobReceived.textContent = MB.toString();
        }

        if (b !== null && validateExponentRange(b, p).valid && this.btnCalcBobSecret) {
          this.btnCalcBobSecret.disabled = false;
        }
      }
    }

    this.revalidateAll();
  }

  handleSendBob() {
    if (this.stepState.bobPub === null) return;
    const p = this.getPValue();
    const g = this.getGValue();
    const a = this.getAValue();

    if (this.mode === 'normal') {
      const wireB = document.getElementById('wire-tag-b');
      if (wireB) wireB.textContent = `← B = ${this.stepState.bobPub}`;

      this.stepState.aliceReceived = this.stepState.bobPub;
      if (this.displayAliceReceived) {
        this.displayAliceReceived.textContent = this.stepState.bobPub.toString();
      }

      if (a !== null && validateExponentRange(a, p).valid && this.btnCalcAliceSecret) {
        this.btnCalcAliceSecret.disabled = false;
      }
    } else {
      const tagBIntercept = document.getElementById('tag-b-intercept');
      if (tagBIntercept) tagBIntercept.textContent = `← B = ${this.stepState.bobPub} (Intercepted)`;

      const mA = this.getMAValue();
      const mB = this.getMBValue();

      if (mB !== null && validateExponentRange(mB, p).valid) {
        const KbM = modPow(this.stepState.bobPub, mB, p);
        this.stepState.malloryKb = KbM;
        if (this.displayMalloryKb) {
          this.displayMalloryKb.textContent = KbM.toString();
          this.displayMalloryKb.className = 'metric-display-box secret-compromise';
        }
      }

      if (mA !== null && validateExponentRange(mA, p).valid) {
        const MA = modPow(g, mA, p);
        const tagMaSpoof = document.getElementById('tag-ma-spoof');
        if (tagMaSpoof) tagMaSpoof.textContent = `Fake M_A = ${MA} →`;

        this.stepState.aliceReceived = MA;
        if (this.displayAliceReceived) {
          this.displayAliceReceived.textContent = MA.toString();
        }

        if (a !== null && validateExponentRange(a, p).valid && this.btnCalcAliceSecret) {
          this.btnCalcAliceSecret.disabled = false;
        }
      }
    }

    this.revalidateAll();
  }

  handleCalcAliceSecret() {
    if (this.stepState.aliceReceived === null) return;
    const p = this.getPValue();
    const a = this.getAValue();
    if (!p || !a || !validateExponentRange(a, p).valid) return;

    const Ka = modPow(this.stepState.aliceReceived, a, p);
    this.stepState.aliceSecret = Ka;
    if (this.displayAliceSecret) {
      this.displayAliceSecret.textContent = Ka.toString();
    }

    this.checkVerificationComplete();
    this.revalidateAll();
  }

  handleCalcBobSecret() {
    if (this.stepState.bobReceived === null) return;
    const p = this.getPValue();
    const b = this.getBValue();
    if (!p || !b || !validateExponentRange(b, p).valid) return;

    const Kb = modPow(this.stepState.bobReceived, b, p);
    this.stepState.bobSecret = Kb;
    if (this.displayBobSecret) {
      this.displayBobSecret.textContent = Kb.toString();
    }

    this.checkVerificationComplete();
    this.revalidateAll();
  }

  checkVerificationComplete() {
    const p = this.getPValue();
    const g = this.getGValue();
    const a = this.getAValue();
    const b = this.getBValue();

    if (this.stepState.aliceSecret !== null && this.stepState.bobSecret !== null) {
      if (this.mode === 'normal') {
        const dh = new DiffieHellman(p, g, a, b);
        this.calculatedDH = dh;
        this.renderNormalResults(dh);
      } else {
        const mA = this.getMAValue();
        const mB = this.getMBValue();
        const mitm = new MITMSimulation(p, g, a, b, mA, mB);
        this.calculatedMITM = mitm;
        this.renderMitmResults(mitm);
      }
    } else {
      const side = this.stepState.aliceSecret !== null ? 'Alice' : 'Bob';
      const keyVal = this.stepState.aliceSecret !== null ? this.stepState.aliceSecret : this.stepState.bobSecret;
      this.statusBanner.className = 'status-banner ready';
      this.statusBanner.innerHTML = `
        <h4>${side}'s key: K = ${keyVal}</h4>
        <p>Waiting for the other key.</p>
      `;
    }
  }

  revalidateAll() {
    const p = this.getPValue();
    const g = this.getGValue();
    const a = this.getAValue();
    const b = this.getBValue();
    const mA = this.getMAValue();
    const mB = this.getMBValue();

    let allValid = true;

    // 1. Validate P (Prime Modulus)
    if (p === null) {
      this.feedbackP.innerHTML = `<span class="feedback-info">Enter a prime p.</span>`;
      if (this.inputP) this.inputP.classList.remove('is-valid', 'is-invalid');
      allValid = false;
    } else {
      const pVal = validatePrimeModulus(p);
      if (!pVal.valid) {
        // INSTANT ALERT FOR NON-PRIME MODULUS
        this.feedbackP.innerHTML = `
          <div class="alert-error" role="alert">
            <span class="alert-icon">⚠️</span>
            <span>${pVal.message}</span>
          </div>
        `;
        if (this.inputP) {
          this.inputP.classList.add('is-invalid');
          this.inputP.classList.remove('is-valid');
        }
        allValid = false;
      } else {
        this.feedbackP.innerHTML = `<span class="feedback-success">✓ Modulus p = ${p} is prime.</span>`;
        if (this.inputP) {
          this.inputP.classList.add('is-valid');
          this.inputP.classList.remove('is-invalid');
        }
      }
    }

    // 2. Validate G (Generator)
    if (g === null) {
      this.feedbackG.innerHTML = p && isPrime(p) 
        ? `<span class="feedback-info">Enter a generator g.</span>`
        : `<span class="feedback-info">Set p first.</span>`;
      if (this.inputG) this.inputG.classList.remove('is-valid', 'is-invalid');
      allValid = false;
    } else if (!p || !isPrime(p)) {
      this.feedbackG.innerHTML = `<span class="feedback-error">Cannot validate generator: modulus p must be prime.</span>`;
      if (this.inputG) this.inputG.classList.add('is-invalid');
      allValid = false;
    } else {
      const gVal = validateGeneratorModP(g, p);
      if (!gVal.valid) {
        let suggestionHtml = '';
        if (gVal.suggestedGenerators && gVal.suggestedGenerators.length > 0) {
          suggestionHtml = `
            <div class="feedback-suggestions">
              <strong>Suggested valid generators for p = ${p}:</strong><br>
              ${gVal.suggestedGenerators.map(sg => `<span class="suggestion-pill" data-g="${sg}">${sg}</span>`).join('')}
            </div>
          `;
        }
        this.feedbackG.innerHTML = `
          <div class="alert-error" role="alert">
            <span class="alert-icon">⚠️</span>
            <span>${gVal.message}</span>
          </div>
          ${suggestionHtml}
        `;
        if (this.inputG) {
          this.inputG.classList.add('is-invalid');
          this.inputG.classList.remove('is-valid');
        }
        allValid = false;

        // Suggested pill click event
        this.feedbackG.querySelectorAll('.suggestion-pill').forEach(pill => {
          pill.addEventListener('click', (e) => {
            const chosen = e.currentTarget.getAttribute('data-g');
            if (this.inputG) {
              this.inputG.value = chosen;
              this.handleGChange();
            }
          });
        });
      } else {
        this.feedbackG.innerHTML = `<span class="feedback-success">✓ Valid generator: g = ${g} is valid.</span>`;
        if (this.inputG) {
          this.inputG.classList.add('is-valid');
          this.inputG.classList.remove('is-invalid');
        }
      }
    }

    // 3. Validate A (Alice Exponent)
    if (a === null) {
      this.feedbackA.innerHTML = p && isPrime(p)
        ? `<span class="feedback-info">Enter Alice's exponent.</span>`
        : `<span class="feedback-info">Set p first.</span>`;
      if (this.inputA) this.inputA.classList.remove('is-valid', 'is-invalid');
      allValid = false;
    } else if (!p || !isPrime(p)) {
      this.feedbackA.innerHTML = `<span class="feedback-error">Enter a valid prime p first.</span>`;
      if (this.inputA) this.inputA.classList.add('is-invalid');
      allValid = false;
    } else {
      const aVal = validateExponentRange(a, p, "Alice's private exponent a");
      if (!aVal.valid) {
        this.feedbackA.innerHTML = `
          <div class="alert-error" role="alert">
            <span class="alert-icon">⚠️</span>
            <span>${aVal.message}</span>
          </div>
        `;
        if (this.inputA) {
          this.inputA.classList.add('is-invalid');
          this.inputA.classList.remove('is-valid');
        }
        allValid = false;
      } else {
        this.feedbackA.innerHTML = `<span class="feedback-success">✓ a = ${a} is valid.</span>`;
        if (this.inputA) {
          this.inputA.classList.add('is-valid');
          this.inputA.classList.remove('is-invalid');
        }
      }
    }

    // 4. Validate B (Bob Exponent)
    if (b === null) {
      this.feedbackB.innerHTML = p && isPrime(p)
        ? `<span class="feedback-info">Enter Bob's exponent.</span>`
        : `<span class="feedback-info">Set p first.</span>`;
      if (this.inputB) this.inputB.classList.remove('is-valid', 'is-invalid');
      allValid = false;
    } else if (!p || !isPrime(p)) {
      this.feedbackB.innerHTML = `<span class="feedback-error">Enter a valid prime p first.</span>`;
      if (this.inputB) this.inputB.classList.add('is-invalid');
      allValid = false;
    } else {
      const bVal = validateExponentRange(b, p, "Bob's private exponent b");
      if (!bVal.valid) {
        this.feedbackB.innerHTML = `
          <div class="alert-error" role="alert">
            <span class="alert-icon">⚠️</span>
            <span>${bVal.message}</span>
          </div>
        `;
        if (this.inputB) {
          this.inputB.classList.add('is-invalid');
          this.inputB.classList.remove('is-valid');
        }
        allValid = false;
      } else {
        this.feedbackB.innerHTML = `<span class="feedback-success">✓ b = ${b} is valid.</span>`;
        if (this.inputB) {
          this.inputB.classList.add('is-valid');
          this.inputB.classList.remove('is-invalid');
        }
      }
    }

    // 5. MITM Exponents (mA, mB)
    if (this.mode === 'mitm') {
      if (mA === null) {
        this.feedbackMA.innerHTML = p && isPrime(p)
          ? `<span class="feedback-info">Enter m_A.</span>`
          : `<span class="feedback-info">Set p first.</span>`;
        if (this.inputMA) this.inputMA.classList.remove('is-valid', 'is-invalid');
        allValid = false;
      } else if (!p || !isPrime(p)) {
        this.feedbackMA.innerHTML = `<span class="feedback-error">Enter a valid prime p first.</span>`;
        allValid = false;
      } else {
        const maVal = validateExponentRange(mA, p, "Mallory's exponent m_A");
        if (!maVal.valid) {
          this.feedbackMA.innerHTML = `
            <div class="alert-error" role="alert">
              <span class="alert-icon">⚠️</span>
              <span>${maVal.message}</span>
            </div>
          `;
          if (this.inputMA) this.inputMA.classList.add('is-invalid');
          allValid = false;
        } else {
          this.feedbackMA.innerHTML = `<span class="feedback-success">✓ m_A = ${mA} is valid.</span>`;
          if (this.inputMA) this.inputMA.classList.add('is-valid');
        }
      }

      if (mB === null) {
        this.feedbackMB.innerHTML = p && isPrime(p)
          ? `<span class="feedback-info">Enter m_B.</span>`
          : `<span class="feedback-info">Set p first.</span>`;
        if (this.inputMB) this.inputMB.classList.remove('is-valid', 'is-invalid');
        allValid = false;
      } else if (!p || !isPrime(p)) {
        this.feedbackMB.innerHTML = `<span class="feedback-error">Enter a valid prime p first.</span>`;
        allValid = false;
      } else {
        const mbVal = validateExponentRange(mB, p, "Mallory's exponent m_B");
        if (!mbVal.valid) {
          this.feedbackMB.innerHTML = `
            <div class="alert-error" role="alert">
              <span class="alert-icon">⚠️</span>
              <span>${mbVal.message}</span>
            </div>
          `;
          if (this.inputMB) this.inputMB.classList.add('is-invalid');
          allValid = false;
        } else {
          this.feedbackMB.innerHTML = `<span class="feedback-success">✓ m_B = ${mB} is valid.</span>`;
          if (this.inputMB) this.inputMB.classList.add('is-valid');
        }
      }
    }

    // In-step buttons enablement based on valid inputs:
    const isPValid = (p !== null && isPrime(p));
    const isGValid = isPValid && (g !== null && isPrimitiveRoot(g, p));
    const isAValid = isPValid && (a !== null && validateExponentRange(a, p).valid);
    const isBValid = isPValid && (b !== null && validateExponentRange(b, p).valid);
    const isMAValid = isPValid && (mA !== null && validateExponentRange(mA, p).valid);
    const isMBValid = isPValid && (mB !== null && validateExponentRange(mB, p).valid);
    const isMitm = this.mode === 'mitm';
    const publicKeysReady = this.stepState.alicePub !== null && this.stepState.bobPub !== null;

    if (this.inputMA) this.inputMA.disabled = !isPValid;
    if (this.inputMB) this.inputMB.disabled = !isPValid;
    if (this.btnGenerateMA) this.btnGenerateMA.disabled = !isPValid;
    if (this.btnGenerateMB) this.btnGenerateMB.disabled = !isPValid;

    if (this.btnCalcAlicePub) {
      this.btnCalcAlicePub.disabled = !(isPValid && isGValid && isAValid);
    }
    if (this.btnCalcBobPub) {
      this.btnCalcBobPub.disabled = !(isPValid && isGValid && isBValid && (!isMitm || this.stepState.alicePub !== null));
    }
    if (this.btnSendAlice) {
      this.btnSendAlice.disabled = isMitm
        ? !(this.stepState.alicePub !== null && isMAValid && isMBValid)
        : (this.stepState.alicePub === null);
    }
    if (this.btnSendBob) {
      this.btnSendBob.disabled = isMitm
        ? !(this.stepState.bobPub !== null && this.stepState.malloryKa !== null)
        : (this.stepState.bobPub === null);
    }
    if (this.btnCalcAliceSecret) {
      this.btnCalcAliceSecret.disabled = isMitm
        ? !(this.stepState.aliceReceived !== null && isAValid && this.stepState.malloryKb !== null)
        : !(this.stepState.aliceReceived !== null && isAValid);
    }
    if (this.btnCalcBobSecret) {
      this.btnCalcBobSecret.disabled = isMitm
        ? !(this.stepState.bobReceived !== null && isBValid && this.stepState.aliceSecret !== null)
        : !(this.stepState.bobReceived !== null && isBValid);
    }

    this.btnCalculate.disabled = !allValid;
    const calcHint = document.querySelector('.calc-hint');
    if (calcHint) {
      calcHint.textContent = allValid
        ? 'Ready to calculate.'
        : 'Enter valid values to continue.';
    }

    return allValid;
  }

  handleCalculate() {
    if (!this.revalidateAll()) return;

    const p = this.getPValue();
    const g = this.getGValue();
    const a = this.getAValue();
    const b = this.getBValue();

    if (this.mode === 'normal') {
      const dh = new DiffieHellman(p, g, a, b);
      this.calculatedDH = dh;

      // Update internal stepState
      this.stepState.alicePub = dh.A;
      this.stepState.bobPub = dh.B;
      this.stepState.aliceReceived = dh.B;
      this.stepState.bobReceived = dh.A;
      this.stepState.aliceSecret = dh.Ka;
      this.stepState.bobSecret = dh.Kb;

      this.renderNormalResults(dh);
    } else {
      const mA = this.getMAValue();
      const mB = this.getMBValue();
      const mitm = new MITMSimulation(p, g, a, b, mA, mB);
      this.calculatedMITM = mitm;

      // Update internal stepState
      this.stepState.alicePub = mitm.A;
      this.stepState.bobPub = mitm.B;
      this.stepState.aliceReceived = mitm.MA;
      this.stepState.bobReceived = mitm.MB;
      this.stepState.aliceSecret = mitm.KaAlice;
      this.stepState.bobSecret = mitm.KbBob;
      this.stepState.malloryKa = mitm.KaMallory;
      this.stepState.malloryKb = mitm.KbMallory;

      this.renderMitmResults(mitm);
    }

    // Enable all step buttons since full calculation completed
    if (this.btnSendAlice) this.btnSendAlice.disabled = false;
    if (this.btnSendBob) this.btnSendBob.disabled = false;
    if (this.btnCalcAliceSecret) this.btnCalcAliceSecret.disabled = false;
    if (this.btnCalcBobSecret) this.btnCalcBobSecret.disabled = false;
  }

  renderNormalResults(dh) {
    // 1. Update 2D Node Cards
    this.displayAlicePriv.textContent = dh.a.toString();
    this.displayAlicePub.textContent = dh.A.toString();
    this.displayAliceSecret.textContent = dh.Ka.toString();
    this.displayAliceSecret.className = 'metric-display-box metric-value secret-match';

    this.displayBobPriv.textContent = dh.b.toString();
    this.displayBobPub.textContent = dh.B.toString();
    this.displayBobSecret.textContent = dh.Kb.toString();
    this.displayBobSecret.className = 'metric-display-box metric-value secret-match';

    if (this.displayAliceReceived) this.displayAliceReceived.textContent = dh.B.toString();
    if (this.displayBobReceived) this.displayBobReceived.textContent = dh.A.toString();

    // Update Public Channel Badges
    const wireA = document.getElementById('wire-tag-a');
    const wireB = document.getElementById('wire-tag-b');
    if (wireA) wireA.textContent = `A = ${dh.A} →`;
    if (wireB) wireB.textContent = `← B = ${dh.B}`;

    // 2. Status Banner (Matching Educational Reference Step 3)
    this.statusBanner.className = 'status-banner success';
    this.statusBanner.innerHTML = `
      <h4>Shared Secret Established: K = ${dh.Ka} (Matching ✓)</h4>
      <p>Shared key established: K = ${dh.Ka} ✓</p>
    `;

    // 3. Mathematical Calculations (Clean math formatting, NO raw LaTeX strings)
    this.resultsFormulas.innerHTML = `
      <div class="formula-card">
        <div class="formula-card-title">1. Alice Computes Public Key A</div>
        <div class="math-display-box">
          A = gᵃ mod p<br>
          <span class="sub-calc">A = ${dh.g}^${dh.a} mod ${dh.p}</span> = <span class="final-res">${dh.A}</span>
        </div>
      </div>

      <div class="formula-card">
        <div class="formula-card-title">2. Bob Computes Public Key B</div>
        <div class="math-display-box">
          B = gᵇ mod p<br>
          <span class="sub-calc">B = ${dh.g}^${dh.b} mod ${dh.p}</span> = <span class="final-res">${dh.B}</span>
        </div>
      </div>

      <div class="formula-card">
        <div class="formula-card-title">3. Alice Derives Shared Secret K_Alice</div>
        <div class="math-display-box">
          K_Alice = Bᵃ mod p<br>
          <span class="sub-calc">K_Alice = ${dh.B}^${dh.a} mod ${dh.p}</span> = <span class="final-res">${dh.Ka}</span>
        </div>
      </div>

      <div class="formula-card">
        <div class="formula-card-title">4. Bob Derives Shared Secret K_Bob</div>
        <div class="math-display-box">
          K_Bob = Aᵇ mod p<br>
          <span class="sub-calc">K_Bob = ${dh.A}^${dh.b} mod ${dh.p}</span> = <span class="final-res">${dh.Kb}</span>
        </div>
      </div>

      <div class="formula-card full-width">
        <div class="formula-card-title">5. Mathematical Identity & Verification Proof</div>
        <div class="math-display-box" style="font-size: 0.98rem;">
          (gᵇ)ᵃ &equiv; gᵃᵇ &equiv; (gᵃ)ᵇ (mod p)<br>
          <span class="sub-calc">(${dh.g}^${dh.b})^${dh.a} &equiv; ${dh.g}^(${dh.a} &times; ${dh.b}) &equiv; (${dh.g}^${dh.a})^${dh.b} &equiv; <strong>${dh.Ka}</strong> (mod ${dh.p})</span>
        </div>
      </div>
    `;

    // Render Steps sequence
    this.renderStepsSequence(dh.getSteps());
  }

  renderMitmResults(mitm) {
    // 1. Update 2D Node Cards
    this.displayAlicePriv.textContent = mitm.a.toString();
    this.displayAlicePub.textContent = mitm.A.toString();
    this.displayAliceSecret.textContent = mitm.KaAlice.toString();
    this.displayAliceSecret.className = 'metric-display-box metric-value secret-compromise';

    this.displayBobPriv.textContent = mitm.b.toString();
    this.displayBobPub.textContent = mitm.B.toString();
    this.displayBobSecret.textContent = mitm.KbBob.toString();
    this.displayBobSecret.className = 'metric-display-box metric-value secret-compromise';

    if (this.displayAliceReceived) this.displayAliceReceived.textContent = mitm.MA.toString();
    if (this.displayBobReceived) this.displayBobReceived.textContent = mitm.MB.toString();

    this.displayMalloryMapriv.textContent = mitm.mA.toString();
    this.displayMalloryMbpriv.textContent = mitm.mB.toString();
    this.displayMalloryMa.textContent = mitm.MA.toString();
    this.displayMalloryMb.textContent = mitm.MB.toString();
    this.displayMalloryKa.textContent = mitm.KaMallory.toString();
    this.displayMalloryKb.textContent = mitm.KbMallory.toString();

    // Update Public Channel Badges
    const tagAIntercept = document.getElementById('tag-a-intercept');
    const tagMaSpoof = document.getElementById('tag-ma-spoof');
    const tagBIntercept = document.getElementById('tag-b-intercept');
    const tagMbSpoof = document.getElementById('tag-mb-spoof');

    if (tagAIntercept) tagAIntercept.textContent = `A = ${mitm.A} (Intercepted)`;
    if (tagMaSpoof) tagMaSpoof.textContent = `Fake M_A = ${mitm.MA} →`;
    if (tagMbSpoof) tagMbSpoof.textContent = `Fake M_B = ${mitm.MB} →`;
    if (tagBIntercept) tagBIntercept.textContent = `← B = ${mitm.B} (Intercepted)`;

    // 2. Status Banner
    this.statusBanner.className = 'status-banner compromised';
    this.statusBanner.innerHTML = `
      <h4>MITM attack succeeded</h4>
      <p>Alice: ${mitm.KaAlice} · Bob: ${mitm.KbBob} · Mallory has both keys.</p>
    `;

    // 3. Mathematical Calculations
    this.resultsFormulas.innerHTML = `
      <div class="formula-card">
        <div class="formula-card-title">Tunnel 1: Alice ⇄ Mallory Key Agreement</div>
        <div class="math-display-box">
          Alice computes: K_Alice = (M_A)ᵃ mod p<br>
          <span class="sub-calc">${mitm.MA}^${mitm.a} mod ${mitm.p}</span> = <span class="final-res">${mitm.KaAlice}</span><br><br>
          Mallory computes: K_Mallory-Alice = A^(m_A) mod p<br>
          <span class="sub-calc">${mitm.A}^${mitm.mA} mod ${mitm.p}</span> = <span class="final-res">${mitm.KaMallory}</span>
        </div>
      </div>

      <div class="formula-card">
        <div class="formula-card-title">Tunnel 2: Mallory ⇄ Bob Key Agreement</div>
        <div class="math-display-box">
          Bob computes: K_Bob = (M_B)ᵇ mod p<br>
          <span class="sub-calc">${mitm.MB}^${mitm.b} mod ${mitm.p}</span> = <span class="final-res">${mitm.KbBob}</span><br><br>
          Mallory computes: K_Mallory-Bob = B^(m_B) mod p<br>
          <span class="sub-calc">${mitm.B}^${mitm.mB} mod ${mitm.p}</span> = <span class="final-res">${mitm.KbMallory}</span>
        </div>
      </div>

      <div class="formula-card full-width">
        <div class="formula-card-title">Cryptographic Vulnerability Analysis</div>
        <div class="math-display-box" style="font-size: 0.95rem;">
          Alice's Key (${mitm.KaAlice}) &ne; Bob's Key (${mitm.KbBob})<br>
          <span class="sub-calc">Mallory negotiates two independent tunnels because unauthenticated Diffie-Hellman lacks cryptographic identity binding.</span>
        </div>
      </div>
    `;

    // Render message tampering demonstration
    this.updateTamperDemo();
  }

  updateTamperDemo() {
    if (!this.calculatedMITM || !this.tamperOutputArea) return;

    const originalMsg = this.tamperInputMsg && this.tamperInputMsg.value.trim() !== ''
      ? this.tamperInputMsg.value.trim()
      : 'Transfer $1,000 from Alice to Bob';

    const t = this.calculatedMITM.simulateTamperedMessage(originalMsg);

    this.tamperOutputArea.innerHTML = `
      <div class="tamper-chain">
        <div class="tamper-node-box alice">
          <div class="tamper-node-label" style="color: var(--color-primary);">1. Alice's Outgoing Transmission</div>
          <div>Plaintext: <span class="tamper-text">"${t.aliceOriginal}"</span></div>
          <div style="font-size: 0.84rem; color: var(--text-muted); margin-top: 2px;">
            Encrypted with Alice's Key (K_Alice = ${t.aliceKey}): <code style="font-family: var(--font-mono); font-weight: 700;">${t.encryptedByAlice}</code>
          </div>
        </div>

        <div class="tamper-node-box mallory">
          <div class="tamper-node-label" style="color: var(--color-danger);">2. Mallory In-Path Interception & Manipulation</div>
          <div>Mallory decrypts with K_Alice (${t.aliceKey}): <span class="tamper-text" style="color: var(--text-muted);">"${t.malloryDecrypted}"</span></div>
          <div style="margin-top: 4px;">
            Mallory tampers message to: <span class="tamper-text" style="color: var(--color-danger);">"${t.malloryTampered}"</span>
          </div>
          <div style="font-size: 0.84rem; color: var(--text-muted); margin-top: 2px;">
            Mallory re-encrypts with Bob's Key (K_Bob = ${t.malloryKeyBob}): <code style="font-family: var(--font-mono); font-weight: 700;">${t.reEncryptedByMallory}</code>
          </div>
        </div>

        <div class="tamper-node-box bob">
          <div class="tamper-node-label" style="color: var(--color-success);">3. Bob's Decrypted Plaintext</div>
          <div>Bob decrypts with K_Bob (${t.malloryKeyBob}): <span class="tamper-text" style="color: var(--color-danger);">"${t.bobReceived}"</span></div>
          <div style="font-size: 0.82rem; color: var(--color-danger); margin-top: 4px;">
            Security Failure: Bob cannot detect that Alice originally sent "$1,000" rather than "$50,000 to Mallory".
          </div>
        </div>
      </div>
    `;
  }

  renderStepsSequence(steps) {
    const container = document.getElementById('tab-pane-steps');
    if (!container) return;

    container.innerHTML = `
      <div class="viva-grid">
        ${steps.map(s => `
          <div class="viva-card">
            <h4 class="viva-q">Stage ${s.stage}: ${s.title}</h4>
            <div class="math-display-box" style="margin-bottom: 8px;">${s.math}</div>
            <p class="viva-a">${s.description}</p>
          </div>
        `).join('')}
      </div>
    `;
  }

  handleReset() {
    if (this.inputP) {
      this.inputP.value = '';
      this.inputP.classList.remove('is-valid', 'is-invalid');
    }
    if (this.inputG) {
      this.inputG.value = '';
      this.inputG.disabled = true;
      this.inputG.placeholder = 'set p first';
      this.inputG.classList.remove('is-valid', 'is-invalid');
    }
    if (this.inputA) {
      this.inputA.value = '';
      this.inputA.disabled = true;
      this.inputA.placeholder = 'set p first';
      this.inputA.classList.remove('is-valid', 'is-invalid');
    }
    if (this.inputB) {
      this.inputB.value = '';
      this.inputB.disabled = true;
      this.inputB.placeholder = 'set p first';
      this.inputB.classList.remove('is-valid', 'is-invalid');
    }
    if (this.inputMA) {
      this.inputMA.value = '';
      this.inputMA.disabled = true;
      this.inputMA.placeholder = 'set p first';
      this.inputMA.classList.remove('is-valid', 'is-invalid');
    }
    if (this.inputMB) {
      this.inputMB.value = '';
      this.inputMB.disabled = true;
      this.inputMB.placeholder = 'set p first';
      this.inputMB.classList.remove('is-valid', 'is-invalid');
    }

    this.currentP = null;
    this.currentG = null;
    this.currentA = null;
    this.currentB = null;
    this.currentMA = null;
    this.currentMB = null;
    this.calculatedDH = null;
    this.calculatedMITM = null;

    this.resetStepCalculations();

    // Reset node values
    this.displayAlicePriv.textContent = '—';
    this.displayAlicePub.textContent = '—';
    this.displayAliceSecret.textContent = '—';
    this.displayAliceSecret.className = 'metric-display-box metric-value';

    this.displayBobPriv.textContent = '—';
    this.displayBobPub.textContent = '—';
    this.displayBobSecret.textContent = '—';
    this.displayBobSecret.className = 'metric-display-box metric-value';

    if (this.displayAliceReceived) this.displayAliceReceived.textContent = '—';
    if (this.displayBobReceived) this.displayBobReceived.textContent = '—';

    this.displayMalloryMapriv.textContent = '—';
    this.displayMalloryMbpriv.textContent = '—';
    this.displayMalloryMa.textContent = '—';
    this.displayMalloryMb.textContent = '—';
    this.displayMalloryKa.textContent = '—';
    this.displayMalloryKb.textContent = '—';

    if (this.btnGenerateG) this.btnGenerateG.disabled = true;
    if (this.btnGenerateA) this.btnGenerateA.disabled = true;
    if (this.btnGenerateB) this.btnGenerateB.disabled = true;
    if (this.btnGenerateMA) this.btnGenerateMA.disabled = true;
    if (this.btnGenerateMB) this.btnGenerateMB.disabled = true;

    if (this.btnCalcAlicePub) this.btnCalcAlicePub.disabled = true;
    if (this.btnCalcBobPub) this.btnCalcBobPub.disabled = true;
    if (this.btnSendAlice) this.btnSendAlice.disabled = true;
    if (this.btnSendBob) this.btnSendBob.disabled = true;
    if (this.btnCalcAliceSecret) this.btnCalcAliceSecret.disabled = true;
    if (this.btnCalcBobSecret) this.btnCalcBobSecret.disabled = true;

    // Status Banner
    this.statusBanner.className = 'status-banner ready';
    this.statusBanner.innerHTML = `
      <h4>Ready</h4>
      <p>Enter the required values above.</p>
    `;

    this.resultsFormulas.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; color: var(--text-muted); padding: 36px 20px;">
        Results appear here after calculation.
      </div>
    `;

    this.revalidateAll();
  }

  loadSuggestedExample() {
    if (this.inputP) {
      this.inputP.value = '23';
      this.handlePChange();
    }

    if (this.inputG) {
      this.inputG.value = '5';
      this.handleGChange();
    }

    if (this.inputA) {
      this.inputA.value = '6';
      this.handleAChange();
    }

    if (this.inputB) {
      this.inputB.value = '15';
      this.handleBChange();
    }

    if (this.inputMA && this.inputMB) {
      this.inputMA.value = '4';
      this.handleMAChange();

      this.inputMB.value = '7';
      this.handleMBChange();
    }

    this.handleCalculate();
  }
}

// Instantiate on DOM ready
window.addEventListener('DOMContentLoaded', () => {
  window.app = new App();
});
