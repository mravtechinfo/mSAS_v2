/**
 * mSAS v2 — Random Number Generator Audit Scanner
 * MASTG Ref: MASTG-CRYPTO-6 (Random Number Generation)
 * CWE-330: Use of Insufficiently Random Values
 */

var MSAS = MSAS || {};
MSAS.RngScanner = (function() {
  'use strict';

  var CWE = 'CWE-330';
  var OWASP = 'M5';
  var MASVS = 'CRYPTO-6';

  var SECURE_RANDOM_SIGS = [
    'Ljava/security/SecureRandom',
    'SecureRandom',
    'SecureRandom.getInstance',
    'Ljava/security/SecureRandomSpi'
  ];

  var INSECURE_RANDOM_SIGS = [
    'Ljava/util/Random',
    'java.util.Random',
    'new java.util.Random',
    'Math.random',
    'Landroid/util/MathUtils',
    'Lkotlin/random/Random',
    'kotlin.random.Random'
  ];

  var PREDICTABLE_SEED_SIGS = [
    'setSeed',
    'Ljava/util/Random;->setSeed',
    'System.currentTimeMillis',
    'System.nanoTime',
    'currentTimeMillis',
    'nanoTime'
  ];

  var RANDOM_CRYPTO_SIGS = [
    'KeyGenerator',
    'Ljavax/crypto/KeyGenerator',
    'KeyPairGenerator',
    'Ljavax/crypto/KeyAgreement',
    'Ljavax/crypto/spec/SecretKeySpec',
    'IvParameterSpec',
    'GCMParameterSpec',
    'PBEKeySpec'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasSecureRandom = MSAS.Utils.hasInStrings(strings, SECURE_RANDOM_SIGS);
    var hasInsecureRandom = MSAS.Utils.hasInStrings(strings, INSECURE_RANDOM_SIGS);
    var hasPredictableSeed = MSAS.Utils.hasInStrings(strings, PREDICTABLE_SEED_SIGS);
    var hasCryptoUsage = MSAS.Utils.hasInStrings(strings, RANDOM_CRYPTO_SIGS);

    if (hasSecureRandom) {
      findings.push({
        ruleId: 'mastg-crypto-6-secure-random',
        ruleName: 'SecureRandom Usage Detected',
        severity: 'secure',
        description: 'App uses SecureRandom for cryptographic randomness. ' +
          'Verify that SecureRandom is properly seeded on older Android versions ' +
          '(pre-4.4 had a bug where /dev/urandom wasn\'t properly seeded). ' +
          'On modern Android, SecureRandom defaults are sufficient.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'SecureRandom usage'
      });
    }

    if (hasInsecureRandom) {
      // Determine if insecure random is used in crypto context
      var criticalUsage = hasInsecureRandom && hasCryptoUsage;

      findings.push({
        ruleId: 'mastg-crypto-6-insecure-random',
        ruleName: hasCryptoUsage
          ? '⚠️ Insecure Random Used for Crypto Operations'
          : 'Insecure Random Number Generator Detected',
        severity: criticalUsage ? 'issue' : 'info',
        description: 'App uses ' + (hasInsecureRandom ? 'java.util.Random or Math.random()' : '') +
          '. These are predictable PRNGs suitable only for non-security use cases ' +
          '(shuffling, animations, etc.). ' +
          (criticalUsage
            ? '⚠️ Cryptographic key/IV generation APIs are also detected alongside ' +
              'insecure randomness. This means keys, IVs, or salts may be generated ' +
              'with predictable values, completely compromising encryption.'
            : 'For security-sensitive randomness (tokens, keys, nonces, passwords), ' +
              'use java.security.SecureRandom.'),
        cwe: criticalUsage ? CWE : '',
        owasp: criticalUsage ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Insecure random' + (criticalUsage ? ' + crypto usage' : '')
      });
    }

    if (hasPredictableSeed && hasInsecureRandom) {
      findings.push({
        ruleId: 'mastg-crypto-6-predictable-seed',
        ruleName: 'Predictable PRNG Seed Detected',
        severity: 'issue',
        description: 'App seeds java.util.Random with predictable values ' +
          '(currentTimeMillis, nanoTime). With knowledge of the approximate seed time, ' +
          'all "random" values can be predicted. Use SecureRandom for ' +
          'security-related randomness.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Predictable seed'
      });
    }

    if (!hasSecureRandom && !hasInsecureRandom) {
      findings.push({
        ruleId: 'mastg-crypto-6-no-random',
        ruleName: 'No Random Number Generators Detected',
        severity: 'info',
        description: 'No Java random number generator references found. ' +
          'If the app generates tokens, session IDs, or cryptographic keys, ' +
          'SecureRandom should be used.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No RNG APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
