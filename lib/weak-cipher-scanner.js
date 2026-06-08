/**
 * mSAS v2 — Weak Cipher Suite Detection Scanner
 * MASTG Ref: MASTG-CRYPTO-3 (Insecure Cipher Suites)
 * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
 */

var MSAS = MSAS || {};
MSAS.WeakCipherScanner = (function() {
  'use strict';

  var CWE = 'CWE-327';
  var OWASP = 'M5';
  var MASVS = 'CRYPTO-3';

  var WEAK_CIPHERS = [
    { name: 'DES/3DES', sigs: ['DES/CBC/NoPadding', 'DES/CBC/PKCS5Padding', 'DESede', 'DESKeySpec', 'Ljavax/crypto/spec/DESKeySpec', 'Ljavax/crypto/spec/DESedeKeySpec'] },
    { name: 'RC2/RC4', sigs: ['RC2', 'RC4', 'ARCFOUR', 'Ljavax/crypto/spec/RC2ParameterSpec'] },
    { name: 'Blowfish', sigs: ['Blowfish', 'Ljavax/crypto/spec/Blowfish'] },
    { name: 'ECB Mode', sigs: ['AES/ECB', '/ECB/NoPadding', '/ECB/PKCS5Padding'] },
    { name: 'RSA NoPadding', sigs: ['RSA/ECB/NoPadding', 'RSA/None/NoPadding'] },
    { name: 'CBC Mode (Padding Oracle)', sigs: ['AES/CBC/PKCS5Padding', 'AES/CBC/PKCS7Padding'] },
    { name: 'NullCipher', sigs: ['Ljavax/crypto/NullCipher', 'NullCipher'] }
  ];

  var WEAK_HASHES = [
    { name: 'MD2', sigs: ['MessageDigest.getInstance("MD2"', 'MessageDigest.getInstance(\'MD2\'', 'MD2'] },
    { name: 'MD4', sigs: ['MessageDigest.getInstance("MD4"', 'MessageDigest.getInstance(\'MD4\'', 'MD4'] },
    { name: 'MD5', sigs: ['MessageDigest.getInstance("MD5"', 'MessageDigest.getInstance(\'MD5\'', 'DigestUtils.md5', '"MD5"'] },
    { name: 'SHA-1', sigs: ['MessageDigest.getInstance("SHA-1"', 'MessageDigest.getInstance("SHA1"', 'DigestUtils.sha1', 'SHA1PRNG'] },
    { name: 'SHA-224', sigs: ['MessageDigest.getInstance("SHA-224"', 'SHA-224'] }
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var weakCiphers = [];
    for (var i = 0; i < WEAK_CIPHERS.length; i++) {
      if (MSAS.Utils.hasInStrings(strings, WEAK_CIPHERS[i].sigs)) {
        weakCiphers.push(WEAK_CIPHERS[i].name);
      }
    }

    var weakHashes = [];
    for (var j = 0; j < WEAK_HASHES.length; j++) {
      if (MSAS.Utils.hasInStrings(strings, WEAK_HASHES[j].sigs)) {
        weakHashes.push(WEAK_HASHES[j].name);
      }
    }

    // Overall weak cipher assessment
    if (weakCiphers.length > 0) {
      findings.push({
        ruleId: 'mastg-crypto-3-weak-ciphers',
        ruleName: 'Weak Cipher Suite' + (weakCiphers.length > 1 ? 's' : '') + ' Detected',
        severity: 'issue',
        description: 'The app uses ' + weakCiphers.length + ' weak cipher' +
          (weakCiphers.length > 1 ? 's' : '') + ': ' + weakCiphers.join(', ') + '. ' +
          'These ciphers have known cryptographic weaknesses. ' +
          'Use AES-256-GCM for symmetric encryption, RSA with OAEP padding for asymmetric, ' +
          'and avoid ECB/CBC modes entirely.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Weak ciphers: ' + weakCiphers.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-crypto-3-no-weak-ciphers',
        ruleName: 'No Weak Cipher Suites Detected',
        severity: 'secure',
        description: 'No references to known weak cipher suites (DES, RC4, ECB, RSA-NoPadding) ' +
          'were found in the DEX strings.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No weak ciphers'
      });
    }

    // Weak hash assessment
    if (weakHashes.length > 0) {
      findings.push({
        ruleId: 'mastg-crypto-4-weak-hashes',
        ruleName: 'Weak Hash Algorithm' + (weakHashes.length > 1 ? 's' : '') + ' Detected',
        severity: 'issue',
        description: 'The app uses ' + weakHashes.length + ' weak hash algorithm' +
          (weakHashes.length > 1 ? 's' : '') + ': ' + weakHashes.join(', ') + '. ' +
          'MD5, SHA-1, and similar weak hashes are vulnerable to collision attacks. ' +
          'Use SHA-256/SHA-3 for integrity and HMAC-SHA256 for authentication.',
        cwe: CWE,
        owasp: OWASP,
        masvs: 'CRYPTO-4',
        file: 'classes.dex',
        line: null,
        match: 'Weak hashes: ' + weakHashes.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-crypto-4-no-weak-hashes',
        ruleName: 'No Weak Hash Algorithms Detected',
        severity: 'secure',
        description: 'No references to known weak hash algorithms (MD2, MD4, MD5, SHA-1) ' +
          'were found in the DEX strings.',
        cwe: '',
        owasp: '',
        masvs: 'CRYPTO-4',
        file: '',
        line: null,
        match: 'No weak hashes'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
