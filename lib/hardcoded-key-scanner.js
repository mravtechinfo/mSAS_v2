/**
 * mSAS v2 — Hardcoded Crypto Keys Scanner
 * MASTG Ref: MASTG-CRYPTO-1 (Symmetric Key Storage) / MASTG-CRYPTO-4 (Static Keys)
 * CWE-321: Use of Hard-coded Cryptographic Key
 */

var MSAS = MSAS || {};
MSAS.HardcodedKeyScanner = (function() {
  'use strict';

  var CWE = 'CWE-321';
  var OWASP = 'M5';
  var MASVS = 'CRYPTO-1';

  var KEY_DERIVATION_SIGS = [
    'Ljavax/crypto/spec/SecretKeySpec',
    'SecretKeySpec',
    'Ljavax/crypto/spec/PBEKeySpec',
    'PBEKeySpec',
    'PBEParameterSpec',
    'PBKDF2',
    'Ljavax/crypto/SecretKeyFactory',
    'SecretKeyFactory',
    'generateSecret',
    'Ljavax/crypto/spec/PBEParameterSpec'
  ];

  var KEYSTORE_FILE_SIGS = [
    '.jks',
    '.bks',
    '.p12',
    '.pfx',
    '.keystore',
    'JKS',
    'BKS',
    'PKCS12',
    'PKCS11'
  ];

  var BASE64_KEY_SIGS = [
    'Landroid/util/Base64',
    'Ljava/util/Base64',
    'Base64.decode',
    'Base64.encode',
    'DatatypeConverter',
    'parseBase64Binary',
    'printBase64Binary'
  ];

  var SECURE_RANDOM_SIGS = [
    'Ljavax/crypto/spec/PBEKeySpec;->PBEKeySpec',
    'Ljava/security/SecureRandom',
    'SecureRandom',
    'Ljavax/crypto/KeyGenerator',
    'KeyGenerator',
    'Ljavax/crypto/KeyAgreement',
    'KeyAgreement'
  ];

  var NONCE_IV_SIGS = [
    'Ljavax/crypto/spec/IvParameterSpec',
    'IvParameterSpec',
    'Ljavax/crypto/spec/GCMParameterSpec',
    'GCMParameterSpec',
    'Ljavax/crypto/spec/AEADBadTagException'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var files = opts.files || [];
    var findings = [];

    var hasKeyDerivation = MSAS.Utils.hasInStrings(strings, KEY_DERIVATION_SIGS);
    var hasKeystoreFiles = MSAS.Utils.hasInStrings(strings, KEYSTORE_FILE_SIGS);
    var hasBase64Key = MSAS.Utils.hasInStrings(strings, BASE64_KEY_SIGS);
    var hasSecureRandom = MSAS.Utils.hasInStrings(strings, SECURE_RANDOM_SIGS);
    var hasNonceIV = MSAS.Utils.hasInStrings(strings, NONCE_IV_SIGS);

    // Also check for actual keystore files in the APK zip
    var hasEmbeddedKeystore = false;
    for (var i = 0; i < files.length; i++) {
      var fname = typeof files[i] === 'string' ? files[i] : (files[i].name || '');
      if (fname.match(/\.(jks|bks|p12|pfx|keystore)$/i)) {
        hasEmbeddedKeystore = true;
        break;
      }
    }

    // Key material usage assessment
    if (hasKeyDerivation) {
      findings.push({
        ruleId: 'mastg-crypto-1-key-material',
        ruleName: 'Cryptographic Key Material Detected',
        severity: 'info',
        description: 'The app uses cryptographic key material APIs (SecretKeySpec, ' +
          'PBEKeySpec, SecretKeyFactory). Verify that keys are not hardcoded in the code ' +
          'and are instead derived from user-provided passphrases or stored in ' +
          'Android KeyStore / iOS Keychain.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Key material APIs in use'
      });
    }

    // Embedded keystore files
    if (hasEmbeddedKeystore) {
      findings.push({
        ruleId: 'mastg-crypto-1-embedded-keystore',
        ruleName: 'Embedded Keystore File Detected',
        severity: 'issue',
        description: 'Keystore file (.jks, .bks, .p12) found embedded in the APK. ' +
          'Embedded keystores protected only by a password can be extracted and ' +
          'brute-forced offline. Store keystores server-side or use KeyStore-backed ' +
          'Android Keystore / iOS Keychain.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Embedded keystore file'
      });
    }

    // Base64 key decoding detection
    if (hasBase64Key && hasKeyDerivation) {
      findings.push({
        ruleId: 'mastg-crypto-1-base64-keys',
        ruleName: 'Base64 Key Decoding Detected',
        severity: 'issue',
        description: 'App decodes Base64 data and uses key material APIs. This pattern ' +
          'suggests cryptographic keys may be stored as Base64-encoded strings in the ' +
          'code or resources, which are trivially extractable by reversing. Use ' +
          'hardware-backed keystore instead.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Base64 decode + key material'
      });
    }

    // Nonce/IV usage assessment
    if (hasNonceIV) {
      findings.push({
        ruleId: 'mastg-crypto-1-nonce-iv',
        ruleName: 'Nonce/IV Parameter Usage',
        severity: 'info',
        description: 'App uses IvParameterSpec or GCMParameterSpec. Verify that ' +
          'initialization vectors are generated with SecureRandom and are unique ' +
          'per encryption operation. Reused IVs with AES-GCM or CBC completely ' +
          'compromises confidentiality.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'IV/Nonce usage'
      });
    }

    // No keys at all
    if (!hasKeyDerivation && !hasEmbeddedKeystore && !hasNonceIV) {
      findings.push({
        ruleId: 'mastg-crypto-1-no-keys',
        ruleName: 'No Cryptographic Key Material Detected',
        severity: 'info',
        description: 'No references to symmetric key or IV material were found. ' +
          'If the app performs encryption, keys should be stored in Android KeyStore ' +
          'or iOS Keychain.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No key material'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
