/**
 * mSAS v2 — Custom Crypto Detection Scanner
 * MASTG Ref: MASTG-CRYPTO-5 (Custom Cryptographic Implementations)
 * CWE-760: Use of a One-Way Hash with a Predictable Salt
 */

var MSAS = MSAS || {};
MSAS.CustomCryptoScanner = (function() {
  'use strict';

  var CWE = 'CWE-760';
  var OWASP = 'M5';
  var MASVS = 'CRYPTO-5';

  var CUSTOM_CRYPTO_SIGS = [
    'Ljavax/crypto/Cipher',
    'Ljavax/crypto/Mac',
    'Ljavax/crypto/spec/SecretKeySpec',
    'Cipher.getInstance',
    'Mac.getInstance',
    'doFinal',
    'update'
  ];

  var MESSAGE_DIGEST_SIGS = [
    'Ljavax/crypto/Cipher',
    'Ljava/security/MessageDigest',
    'MessageDigest',
    'getInstance',
    'digest',
    'Ljava/security/DigestInputStream',
    'Ljava/security/DigestOutputStream'
  ];

  var PREDICTABLE_SALT_SIGS = [
    'salt',
    'PBEKeySpec',
    'PBEParameterSpec',
    'getSalt',
    'setSalt',
    'staticSalt',
    'SALT',
    'SALT_VALUE',
    'PBKDF2WithHmacSHA1',
    'PBKDF2WithHmacSHA256',
    'PBKDF2WithHmacSHA512'
  ];

  var CUSTOM_ALGORITHM_SIGS = [
    'myEncrypt',
    'myDecrypt',
    'customCipher',
    'CustomCipher',
    'encryptData',
    'decryptData',
    'xorEncrypt',
    'xorDecrypt',
    'obfuscate',
    'deobfuscate',
    'scramble',
    'unscramble'
  ];

  var WEAK_PROVIDER_SIGS = [
    'Lorg/bouncycastle/crypto',
    'org.bouncycastle',
    'Lorg/spongycastle/crypto',
    'org.spongycastle',
    'BC',
    'BouncyCastle',
    'SpongyCastle',
    'Security.insertProviderAt',
    'Security.addProvider'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasCustomCrypto = MSAS.Utils.hasInStrings(strings, CUSTOM_CRYPTO_SIGS);
    var hasMessageDigest = MSAS.Utils.hasInStrings(strings, MESSAGE_DIGEST_SIGS);
    var hasSalt = MSAS.Utils.hasInStrings(strings, PREDICTABLE_SALT_SIGS);
    var hasCustomAlgo = MSAS.Utils.hasInStrings(strings, CUSTOM_ALGORITHM_SIGS);
    var hasWeakProvider = MSAS.Utils.hasInStrings(strings, WEAK_PROVIDER_SIGS);

    // Standard crypto usage
    if (hasCustomCrypto || hasMessageDigest) {
      var cryptoTypes = [];
      if (hasCustomCrypto) cryptoTypes.push('Cipher/Mac');
      if (hasMessageDigest) cryptoTypes.push('MessageDigest');

      findings.push({
        ruleId: 'mastg-crypto-5-crypto-usage',
        ruleName: 'Cryptographic API Usage',
        severity: 'info',
        description: 'App uses standard Java cryptographic APIs (' +
          cryptoTypes.join(', ') + '). Verify that standard provider implementations ' +
          'are used rather than custom rolling crypto. Prefer high-level libraries ' +
          'like Tink, Conscrypt, or Android Jetpack Security.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: cryptoTypes.join(', ')
      });
    }

    // Custom algorithm detection
    if (hasCustomAlgo) {
      findings.push({
        ruleId: 'mastg-crypto-5-custom-algorithm',
        ruleName: 'Custom Cryptographic Algorithm',
        severity: 'issue',
        description: 'App defines custom encryption/decryption or obfuscation methods. ' +
          'Custom cryptography is almost always insecure. Use standard, audited ' +
          'algorithms (AES-GCM, ChaCha20-Poly1305, X25519) via well-known providers.',
        cwe: 'CWE-327',
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Custom crypto methods'
      });
    }

    // Salt usage
    if (hasSalt) {
      findings.push({
        ruleId: 'mastg-crypto-5-static-salt',
        ruleName: 'Salt/PBE Usage Detected',
        severity: hasCustomAlgo ? 'issue' : 'info',
        description: 'App uses password-based encryption (PBE) with salt parameters. ' +
          'Verify that salts are generated using SecureRandom for each password ' +
          'derivation and are not hardcoded. Static salts defeat the purpose of salting ' +
          'against rainbow table attacks.',
        cwe: hasCustomAlgo ? CWE : '',
        owasp: hasCustomAlgo ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'PBE/salt usage'
      });
    }

    // Third-party provider detection
    if (hasWeakProvider) {
      findings.push({
        ruleId: 'mastg-crypto-5-third-party-provider',
        ruleName: 'Third-Party Crypto Provider',
        severity: 'info',
        description: 'App uses a third-party cryptographic provider (BouncyCastle, ' +
          'SpongyCastle). Verify the provider version is up-to-date and that it is ' +
          'not used to bypass platform crypto restrictions. On Android P+, ' +
          'BouncyCastle is deprecated in favor of Conscrypt.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasWeakProvider ? 'Third-party provider' : ''
      });
    }

    // No crypto at all
    if (!hasCustomCrypto && !hasMessageDigest && !hasCustomAlgo) {
      findings.push({
        ruleId: 'mastg-crypto-5-no-crypto',
        ruleName: 'No Cryptographic APIs Detected',
        severity: 'info',
        description: 'No cryptographic APIs were detected. If the app handles ' +
          'sensitive data, verify encryption is implemented.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No crypto APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
