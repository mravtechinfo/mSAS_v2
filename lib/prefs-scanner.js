/**
 * mSAS v2 — SharedPreferences Audit Scanner
 * 
 * Scans APK for SharedPreferences usage patterns:
 * - getSharedPreferences() / getPreferences() API calls
 * - MODE_WORLD_READABLE / MODE_WORLD_WRITEABLE flags
 * - EncryptedSharedPreferences (encrypted vs unencrypted)
 * - Jetpack DataStore (modern alternative)
 * 
 * Outputs v1-compatible findings: { ruleId, ruleName, severity, description, cwe, owasp, masvs, file, line, match }
 */

var MSAS = MSAS || {};
MSAS.PrefsScanner = (function() {
  'use strict';

  var CWE_STORAGE = 'CWE-312';
  var OWASP_M2 = 'M2';
  var MASVS_STORAGE = 'STORAGE-1';

  /** SharedPreferences API signatures to search in DEX strings */
  var PREFS_SIGS = [
    'SharedPreferences',
    'getSharedPreferences',
    'getPreferences',
    'PreferenceManager',
    'android.content.SharedPreferences'
  ];

  /** Encryption-related signatures */
  var ENCRYPTED_SIGS = [
    'EncryptedSharedPreferences',
    'MasterKey',
    'MasterKeys',
    'androidx.security.crypto'
  ];

  /** World mode flags */
  var MODE_WORLD_READABLE_SIGS = [
    'MODE_WORLD_READABLE',
    'Context.MODE_WORLD_READABLE'
  ];

  var MODE_WORLD_WRITEABLE_SIGS = [
    'MODE_WORLD_WRITEABLE',
    'Context.MODE_WORLD_WRITEABLE'
  ];

  /** Jetpack DataStore signatures (modern replacement for SharedPreferences) */
  var DATASTORE_SIGS = [
    'DataStore',
    'DataStoreFactory',
    'androidx.datastore',
    'preferencesDataStore',
    'createDataStore'
  ];

  /**
   * Main scan function — produces v1-compatible findings
   */
  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasPrefsApi    = hasInStrings(strings, PREFS_SIGS);
    var hasEncrypted   = hasInStrings(strings, ENCRYPTED_SIGS);
    var hasWorldRead   = hasInStrings(strings, MODE_WORLD_READABLE_SIGS);
    var hasWorldWrite  = hasInStrings(strings, MODE_WORLD_WRITEABLE_SIGS);
    var hasDataStore   = hasInStrings(strings, DATASTORE_SIGS);

    // 1. SharedPreferences API usage
    if (hasPrefsApi) {
      var usedApi = findInStrings(strings, PREFS_SIGS);
      findings.push({
        ruleId: 'mastg-storage-1-sharedprefs-usage',
        ruleName: hasEncrypted
          ? 'SharedPreferences with Encryption (EncryptedSharedPreferences)'
          : 'SharedPreferences API Usage (unencrypted)',
        severity: hasEncrypted ? 'info' : 'issue',
        description: hasEncrypted
          ? 'App uses EncryptedSharedPreferences for secure key-value storage. Verify the MasterKey is configured ' +
            'with KeyGenParameterSpec (not a hardcoded fallback) and that AES256_GCM is the preferred encryption scheme.'
          : 'App uses SharedPreferences API: ' + usedApi.slice(0, 3).join(', ') + '. ' +
            'SharedPreferences stores data as plain XML in /data/data/<pkg>/shared_prefs/. ' +
            'Sensitive data (tokens, PII, credentials) must use EncryptedSharedPreferences instead.',
        cwe: hasEncrypted ? '' : CWE_STORAGE,
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: 'classes.dex',
        line: null,
        match: hasEncrypted ? 'EncryptedSharedPreferences detected' : 'Unencrypted SharedPreferences detected'
      });

      // 2. World-readable / world-writable mode flags
      if (hasWorldRead || hasWorldWrite) {
        var modes = [];
        if (hasWorldRead) modes.push('MODE_WORLD_READABLE');
        if (hasWorldWrite) modes.push('MODE_WORLD_WRITEABLE');
        findings.push({
          ruleId: 'mastg-storage-1-sharedprefs-world-mode',
          ruleName: 'SharedPreferences with World-Readable/World-Writable Mode',
          severity: 'issue',
          description: 'SharedPreferences created with ' + modes.join(' and ') + '. ' +
            'These modes allow other installed apps to read and/or write the preference file. ' +
            'MODE_WORLD_READABLE and MODE_WORLD_WRITEABLE were deprecated in API 17 (Android 4.2) and ' +
            'throw a SecurityException on Android 7.0+. Use MODE_PRIVATE with EncryptedSharedPreferences.',
          cwe: 'CWE-276',
          owasp: OWASP_M2,
          masvs: MASVS_STORAGE,
          file: 'classes.dex',
          line: null,
          match: 'Flags: ' + modes.join(', ')
        });
      }
    }

    // 3. Jetpack DataStore detection (positive — modern secure alternative)
    if (hasDataStore) {
      var dsApi = findInStrings(strings, DATASTORE_SIGS);
      findings.push({
        ruleId: 'mastg-storage-1-datastore-usage',
        ruleName: 'Jetpack DataStore Detected',
        severity: 'secure',
        description: 'App uses Jetpack DataStore: ' + dsApi.slice(0, 3).join(', ') + '. ' +
          'DataStore is the recommended replacement for SharedPreferences. It uses an asynchronous, ' +
          'transactional data storage API with built-in corruption protection. ' +
          'Note: DataStore does NOT encrypt data by default. For sensitive data, use DataStore with encryption ' +
          'or combine with EncryptedSharedPreferences for secrets.',
        cwe: '',
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: 'classes.dex',
        line: null,
        match: 'DataStore APIs: ' + dsApi.join(', ')
      });
    }

    // 4. No SharedPreferences or DataStore found
    if (!hasPrefsApi && !hasDataStore) {
      findings.push({
        ruleId: 'mastg-storage-1-no-prefs',
        ruleName: 'No SharedPreferences or DataStore Usage Detected',
        severity: 'secure',
        description: 'No SharedPreferences, EncryptedSharedPreferences, or Jetpack DataStore references were found. ' +
          'The app may not use local key-value storage, or uses a custom persistence mechanism.',
        cwe: '',
        owasp: '',
        masvs: MASVS_STORAGE,
        file: '',
        line: null,
        match: 'No prefs/DataStore APIs found'
      });
    }

    return findings;
  }

  function findInStrings(strings, signatures) {
    var limit = Math.min(strings.length, 50000);
    var found = [];
    for (var i = 0; i < signatures.length; i++) {
      for (var j = 0; j < limit; j++) {
        if (strings[j].indexOf(signatures[i]) >= 0) {
          found.push(signatures[i]);
          break;
        }
      }
    }
    return found;
  }

  function hasInStrings(strings, signatures) {
    return findInStrings(strings, signatures).length > 0;
  }

  return { scan: scan };
})();
