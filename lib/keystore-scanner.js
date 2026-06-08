/**
 * mSAS v2 — Keystore / Keychain Analysis Scanner
 * MASTG Ref: MASTG-STORAGE-5 (Keychain / KeyStore Data Storage)
 * CWE-522: Insufficiently Protected Credentials
 */

var MSAS = MSAS || {};
MSAS.KeystoreScanner = (function() {
  'use strict';

  var CWE = 'CWE-522';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-5';

  var ANDROID_KEYSTORE_SIGS = [
    'Landroid/security/KeyChain',
    'Ljava/security/KeyStore',
    'KeyStore',
    'AndroidKeyStore',
    'KeyStore.getInstance',
    'KeyGenParameterSpec',
    'KeyProtection',
    'Landroid/security/keystore/KeyGenParameterSpec',
    'Landroid/security/keystore/KeyProtection'
  ];

  var IOS_KEYCHAIN_SIGS = [
    'Lapple/security/Keychain',
    'Lsecurity/Security',
    'SecItemAdd',
    'SecItemCopyMatching',
    'SecItemDelete',
    'kSecAttrAccessible',
    'Lcom/apple/security/Keychain'
  ];

  var WEAK_ACCESSIBILITY_SIGS = [
    'kSecAttrAccessibleAlways',
    'kSecAttrAccessibleAlwaysThisDeviceOnly',
    'kSecAttrAccessibleAfterFirstUnlock',
    'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly'
  ];

  var STRONG_ACCESSIBILITY_SIGS = [
    'kSecAttrAccessibleWhenUnlocked',
    'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
    'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly'
  ];

  var SHARED_PREFS_FALLBACK_SIGS = [
    'Landroid/content/SharedPreferences',
    'getSharedPreferences',
    'getPreferences'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasAndroidKeystore = MSAS.Utils.hasInStrings(strings, ANDROID_KEYSTORE_SIGS);
    var hasIosKeychain = MSAS.Utils.hasInStrings(strings, IOS_KEYCHAIN_SIGS);
    var hasWeakAccess = MSAS.Utils.hasInStrings(strings, WEAK_ACCESSIBILITY_SIGS);
    var hasStrongAccess = MSAS.Utils.hasInStrings(strings, STRONG_ACCESSIBILITY_SIGS);
    var hasSharedPrefs = MSAS.Utils.hasInStrings(strings, SHARED_PREFS_FALLBACK_SIGS);

    // Android Keystore assessment
    if (hasAndroidKeystore) {
      findings.push({
        ruleId: 'mastg-storage-5-android-keystore',
        ruleName: 'Android KeyStore Usage Detected',
        severity: 'secure',
        description: 'App uses Android KeyStore API for cryptographic key storage. ' +
          'When properly implemented, KeyStore provides hardware-backed key storage ' +
          'via TEE/StrongBox. Verify that keys are created with KeyGenParameterSpec ' +
          'using proper auth requirements (setUserAuthenticationRequired) and that ' +
          'keys are not extracted for storage elsewhere.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Android KeyStore API'
      });
    } else if (hasSharedPrefs) {
      findings.push({
        ruleId: 'mastg-storage-5-no-keystore',
        ruleName: 'No KeyStore — SharedPreferences Used for Storage',
        severity: 'issue',
        description: 'No Android KeyStore API detected, but SharedPreferences is used. ' +
          'Sensitive data such as auth tokens, keys, or credentials should be stored in ' +
          'Android KeyStore or EncryptedSharedPreferences rather than plain SharedPreferences.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'No KeyStore, SharedPreferences in use'
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-5-no-keystore-data',
        ruleName: 'No KeyStore or Keychain Detected',
        severity: 'info',
        description: 'Neither Android KeyStore nor iOS Keychain references were found. ' +
          'If the app handles sensitive data, secure key storage should be implemented.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No secure storage API'
      });
    }

    // iOS Keychain assessment
    if (hasIosKeychain) {
      var iosSeverity = hasWeakAccess && !hasStrongAccess ? 'issue' : 'secure';
      var iosDesc = hasWeakAccess && !hasStrongAccess
        ? 'iOS Keychain detected with weak kSecAttrAccessible settings. ' +
          'kSecAttrAccessibleAlways or AfterFirstUnlock allows access after device restart ' +
          'before user unlock. Prefer kSecAttrAccessibleWhenUnlockedThisDeviceOnly or ' +
          'kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly.'
        : 'iOS Keychain detected with strong accessibility settings. Verify that ' +
          'kSecAccessControl flags (biometry, user presence) are configured for sensitive data.';

      findings.push({
        ruleId: 'mastg-storage-5-ios-keychain',
        ruleName: 'iOS Keychain Usage Detected' + (hasWeakAccess && !hasStrongAccess ? ' (Weak Settings)' : ''),
        severity: iosSeverity,
        description: iosDesc,
        cwe: hasWeakAccess ? CWE : '',
        owasp: hasWeakAccess ? OWASP : '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'iOS Keychain' + (hasWeakAccess && !hasStrongAccess ? ' — weak accessibility' : '')
      });
    }

    return findings;
  }

  return { scan: scan };
})();
