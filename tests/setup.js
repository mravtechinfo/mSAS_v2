/**
 * mSAS v2 — Test Setup
 * 
 * Loads all MSAS IIFE modules in dependency order so they're available
 * in the global `MSAS` namespace for all test files.
 * 
 * The key challenge: IIFE modules use `var MSAS = MSAS || {};` which creates
 * a function-scoped variable when evaluated via `new Function()`. We strip
 * this line so the module code references the global `global.MSAS` directly.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize global MSAS namespace — matches how browsers use window.MSAS
global.MSAS = {};

// Helper to load a JS file as text and evaluate it in the global scope
function loadLib(filename) {
  const filePath = path.resolve(__dirname, '../lib', filename);
  if (!fs.existsSync(filePath)) {
    console.warn(`[test-setup] WARN: ${filename} not found at ${filePath}`);
    return;
  }
  let code = fs.readFileSync(filePath, 'utf-8');

  // Remove `var MSAS = MSAS || {};` (and similar patterns) so that MSAS
  // references the global `global.MSAS` we set up above.  In a browser
  // these scripts run at the top level where var creates a window property,
  // but inside new Function() var is function-scoped and shadows the outer
  // variable. Stripping the line fixes this.
  code = code.replace(/var\s+MSAS\s*=\s*MSAS\s*\|\|\s*\{\}\s*;\s*/g, '');

  try {
    // Use indirect eval via Function to run in global scope
    const fn = new Function(code);
    fn();
  } catch (e) {
    console.error(`[test-setup] ERROR loading ${filename}:`, e.message);
    throw e;
  }
}

function loadCore(filename) {
  const filePath = path.resolve(__dirname, '../apk-auditor/src/core', filename);
  if (!fs.existsSync(filePath)) {
    console.warn(`[test-setup] WARN: ${filename} not found at ${filePath}`);
    return;
  }
  let code = fs.readFileSync(filePath, 'utf-8');
  code = code.replace(/var\s+MSAS\s*=\s*MSAS\s*\|\|\s*\{\}\s*;\s*/g, '');
  try {
    const fn = new Function(code);
    fn();
  } catch (e) {
    console.error(`[test-setup] ERROR loading ${filename}:`, e.message);
    throw e;
  }
}

// ── Phase 0: Foundation ───────────────────────────────────────
loadLib('test-result.js');   // MSAS.TestResult
loadLib('utils.js');         // MSAS.Utils
loadLib('state-store.js');   // MSAS.StateStore (BASE-3)

// ── BASE-1: Shared Modules ───────────────────────────────────────
loadLib('shared/format.js');      // MSAS.SharedFormat
loadLib('shared/entropy.js');     // MSAS.SharedEntropy
loadLib('shared/registry.js');    // MSAS.SharedRegistry

// ── BASE-2: Declarative Rule Engine ───────────────────────────────
loadLib('rule-engine.js');        // MSAS.RuleEngine

// ── Phase 1: Storage scanners ─────────────────────────────────
loadLib('storage-scanner.js');
loadLib('prefs-scanner.js');
loadLib('log-leakage-scanner.js');
loadLib('firebase-scanner.js');
loadLib('clipboard-scanner.js');
loadLib('screenshot-scanner.js');
loadLib('keystore-scanner.js');
loadLib('notification-scanner.js');
loadLib('analytics-scanner.js');
loadLib('device-access-scanner.js');
loadLib('cache-scanner.js');
loadLib('backup-scanner.js');
loadLib('scoped-storage-scanner.js');

// ── Phase 2: Crypto & Auth scanners ───────────────────────────
loadLib('weak-cipher-scanner.js');
loadLib('cert-validation-scanner.js');
loadLib('hardcoded-key-scanner.js');
loadLib('custom-crypto-scanner.js');
loadLib('rng-scanner.js');
loadLib('pinning-scanner.js');
loadLib('password-policy-scanner.js');
loadLib('session-scanner.js');
loadLib('oauth-scanner.js');
loadLib('auth-bypass-scanner.js');

// ── Phase 3: Network & Platform scanners ──────────────────────
loadLib('tls-config-scanner.js');
loadLib('cleartext-scanner.js');
loadLib('network-sdk-scanner.js');
loadLib('network-security-scanner.js');
loadLib('webview-scanner.js');
loadLib('deeplink-scanner.js');
loadLib('tapjacking-scanner.js');
loadLib('pending-intent-scanner.js');
loadLib('task-affinity-scanner.js');
loadLib('content-provider-scanner.js');
loadLib('components-scanner.js');

// ── Phase 4: Code & Resilience scanners ───────────────────────
loadLib('deserialization-scanner.js');
loadLib('ndk-scanner.js');
loadLib('permission-scanner.js');
loadLib('proguard-scanner.js');
loadLib('re-tool-scanner.js');
loadLib('anti-debug-scanner.js');
loadLib('integrity-scanner.js');
loadLib('root-jailbreak-scanner.js');
loadLib('memory-scanner.js');
loadLib('code-quality-scanner.js');
loadLib('ios-scanners.js');

// ── Phase 5: AI/ML scanners ──────────────────────────────────
loadLib('ai-ml-scanner.js');

// ── Phase 6: ADB scanners ─────────────────────────────────────
loadLib('adb-scanner.js');

// ── Phase 7: Reporting suite ──────────────────────────────────
loadLib('cvss-calculator.js');
loadLib('risk-matrix.js');
loadLib('report-generator.js');
loadLib('evidence-attachment.js');
loadLib('trend-analysis.js');

// ── Phase 8: UX modules ───────────────────────────────────────
loadLib('scan-history.js');
loadLib('batch-analysis.js');
loadLib('rule-editor.js');
loadLib('virtual-scroll.js');

// ── Validation ────────────────────────────────────────────────
const modules = Object.keys(global.MSAS).sort();
console.log(`[test-setup] MSAS modules loaded: ${modules.length}`);
console.log(`[test-setup] Modules: ${modules.join(', ')}`);

// Verify core modules loaded correctly
if (!global.MSAS.Utils) throw new Error('MSAS.Utils not loaded');
if (!global.MSAS.TestResult) throw new Error('MSAS.TestResult not loaded');
if (!global.MSAS.StorageScanner) throw new Error('MSAS.StorageScanner not loaded');
if (!global.MSAS.CVSS) throw new Error('MSAS.CVSS not loaded');
