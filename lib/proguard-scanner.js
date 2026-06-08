/**
 * mSAS v2 — ProGuard/R8 Effectiveness Scanner
 * MASTG Ref: MASTG-CODE-1 (Code Obfuscation)
 * CWE-656: Reliance on Security Through Obscurity
 */

var MSAS = MSAS || {};
MSAS.ProGuardScanner = (function() {
  'use strict';

  var CWE = 'CWE-656';
  var OWASP = 'M9';
  var MASVS = 'CODE-1';

  var PROGUARD_SIGS = [
    'ProGuard',
    'proguard',
    'android:proguard',
    'proguard-android.txt',
    'proguard-rules.pro',
    'proguard-project.txt',
    'PROGUARD',
    'dictionary',
    'obfuscation',
    'Lcom/google/proguard'
  ];

  var OBFUSCATION_SIGS = [
    'a.a.a',
    'a.b.c',
    'b.a',
    'com.a',
    'obfuscated',
    'Obfuscation',
    'obfuscate',
    'mapping.txt',
    'seeds.txt',
    'usage.txt'
  ];

  var STRING_ENCRYPT_SIGS = [
    'Lcom/safetybits',
    'Lcom/proguard',
    'Lcom/dasho',
    'Lcom/guardSquare',
    'StringEncryption',
    'stringDecrypt',
    'decryptString',
    'Decompilation',
    'R8',
    'com.android.tools.r8'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasProGuard = MSAS.Utils.hasInStrings(strings, PROGUARD_SIGS);
    var hasObfuscation = MSAS.Utils.hasInStrings(strings, OBFUSCATION_SIGS);
    var hasStringEncrypt = MSAS.Utils.hasInStrings(strings, STRING_ENCRYPT_SIGS);

    if (hasProGuard || hasObfuscation || hasStringEncrypt) {
      var severity = hasStringEncrypt ? 'secure' : 'info';
      findings.push({
        ruleId: 'mastg-code-1-obfuscation',
        ruleName: hasStringEncrypt
          ? 'Code Obfuscation & String Encryption Detected'
          : 'ProGuard/R8 Obfuscation Detected',
        severity: severity,
        description: 'App uses ' +
          (hasStringEncrypt ? 'string encryption and ' : '') +
          'code obfuscation.' +
          (hasProGuard ? ' ProGuard/R8 references detected.' : '') +
          (hasObfuscation ? ' Obfuscated class/package name patterns detected.' : '') +
          (hasStringEncrypt
            ? ' ✅ String encryption makes reverse engineering more difficult ' +
              'by hiding hardcoded strings from static analysis.'
            : ' Verify that obfuscation is enabled for release builds and that ' +
              'mapping.txt is kept secure.'),
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasProGuard ? 'ProGuard/R8' : '') +
          (hasObfuscation ? (hasProGuard ? ' + ' : '') + 'obfuscation' : '') +
          (hasStringEncrypt ? ' + string encryption' : '')
      });
    }

    if (!hasProGuard && !hasObfuscation && !hasStringEncrypt) {
      findings.push({
        ruleId: 'mastg-code-1-no-obfuscation',
        ruleName: 'No Code Obfuscation Detected',
        severity: 'info',
        description: 'No ProGuard/R8 or code obfuscation references found. ' +
          'Obfuscation (via R8/ProGuard) is recommended for release builds ' +
          'to slow reverse engineering. Enable minification in build.gradle.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No obfuscation'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
