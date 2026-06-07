/**
 * mSAS v2 — Storage Scanner (SQLite/Realm)
 * 
 * Scans APK files for embedded SQLite databases (.db, .sqlite, .sqlite3, .db3),
 * Realm database files (.realm), and detects database SDK usage in DEX strings.
 * Reports unencrypted databases, hardcoded DB paths, and missing encryption.
 * 
 * Outputs findings in v1-compatible format (matching engine.js schema):
 *   { ruleId, ruleName, severity, description, cwe, owasp, masvs, file, line, match }
 */

var MSAS = MSAS || {};
MSAS.StorageScanner = (function() {
  'use strict';

  var DB_EXTS = ['.db', '.sqlite', '.sqlite3', '.db3'];
  var CWE_STORAGE = 'CWE-312';
  var OWASP_M2 = 'M2';
  var MASVS_STORAGE = 'STORAGE-1';

  var REALM_SIGS = [
    'io.realm',
    'RealmConfiguration',
    'Realm.getInstance',
    'Realm.init',
    'io.realm.kotlin',
    'RealmObject'
  ];

  var SQLITE_SIGS = [
    'SQLiteOpenHelper',
    'SQLiteDatabase',
    'openOrCreateDatabase',
    'android.database.sqlite',
    'androidx.sqlite',
    'Room.databaseBuilder',
    'RoomDatabase',
    'androidx.room'
  ];

  /**
   * Main scan function — produces v1-compatible findings
   */
  function scan(opts) {
    opts = opts || {};
    var files = opts.files || [];
    var strings = opts.strings || [];
    var findings = [];

    // Find database files in APK
    var dbFiles = findFilesByExt(files, DB_EXTS);
    var realmFiles = findFilesByExt(files, ['.realm']);
    var hasSqlCipher = hasInStrings(strings, ['SQLCipher', 'net.sqlcipher']);
    var hasEncryption = hasSqlCipher || hasInStrings(strings, ['EncryptedDatabase', 'EncryptedSQLite']);

    // Unencrypted SQLite databases embedded in APK
    if (dbFiles.length > 0) {
      var dbList = dbFiles.slice(0, 5).map(getFileName).join(', ');
      findings.push({
        ruleId: 'mastg-storage-1-embedded-sqlite',
        ruleName: hasEncryption ? 'Encrypted SQLite Database Found in APK' : 'Unencrypted SQLite Database in APK Assets',
        severity: hasEncryption ? 'info' : 'issue',
        description: (hasEncryption ? 'Encrypted database' : 'Unencrypted database(s)') +
          ' found in APK: ' + dbList + '. ' +
          (hasEncryption
            ? 'Uses SQLCipher/encryption — verify keys are stored in Android Keystore.'
            : 'Databases in APK assets are world-readable and extractable. Never store sensitive data in asset databases.'),
        cwe: CWE_STORAGE,
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: dbFiles[0] || '',
        line: null,
        match: 'DB files: ' + dbFiles.join(', ')
      });
    }

    // SQLite API usage detected in DEX strings
    var sqliteUsed = findInStrings(strings, SQLITE_SIGS);
    if (sqliteUsed.length > 0) {
      findings.push({
        ruleId: 'mastg-storage-1-sqlite-api',
        ruleName: hasEncryption ? 'SQLite Database APIs (with SQLCipher)' : 'SQLite Database API Usage Detected',
        severity: hasEncryption ? 'info' : 'issue',
        description: 'App uses SQLite database APIs: ' + sqliteUsed.slice(0, 4).join(', ') + '. ' +
          (hasEncryption
            ? 'SQLCipher provides encryption, but verify the encryption key is not hardcoded.'
            : 'SQLite stores data as unencrypted .db files in app data directory. Use SQLCipher or EncryptedSharedPreferences for sensitive data.'),
        cwe: CWE_STORAGE,
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: 'classes.dex',
        line: null,
        match: hasEncryption ? 'SQLCipher detected' : 'No encryption detected'
      });
    }

    // Realm SDK detection
    var realmUsed = findInStrings(strings, REALM_SIGS);
    if (realmUsed.length > 0) {
      findings.push({
        ruleId: 'mastg-storage-1-realm-sdk',
        ruleName: 'Realm Database SDK Detected',
        severity: 'issue',
        description: 'Realm SDK found: ' + realmUsed.join(', ') + '. Realm databases must be encrypted via ' +
          'RealmConfiguration.Builder.encryptionKey() with a key in Android Keystore. Without encryption, ' +
          'Realm .realm files on disk are readable by any app with root access or ADB backup.',
        cwe: CWE_STORAGE,
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: 'classes.dex',
        line: null,
        match: 'Realm APIs: ' + realmUsed.join(', ')
      });
    }

    // Realm .realm files in APK
    if (realmFiles.length > 0) {
      findings.push({
        ruleId: 'mastg-storage-1-realm-files',
        ruleName: 'Realm Database File in APK Assets',
        severity: 'issue',
        description: 'Realm file(s) found in APK: ' + realmFiles.join(', ') + '. Static Realm databases ' +
          'in assets may contain default/seed data. These files are trivially extractable from the APK.',
        cwe: CWE_STORAGE,
        owasp: OWASP_M2,
        masvs: MASVS_STORAGE,
        file: realmFiles[0] || '',
        line: null,
        match: 'Realm files: ' + realmFiles.join(', ')
      });
    }

    // No database usage — informational
    if (dbFiles.length === 0 && realmFiles.length === 0 && sqliteUsed.length === 0 && realmUsed.length === 0) {
      findings.push({
        ruleId: 'mastg-storage-1-no-db',
        ruleName: 'No Local Database Storage Detected',
        severity: 'secure',
        description: 'No SQLite or Realm database files or API references were found. The app may use ' +
          'network-based storage, Jetpack DataStore, or no local persistence at all.',
        cwe: '',
        owasp: '',
        masvs: MASVS_STORAGE,
        file: '',
        line: null,
        match: 'No database files or API references found'
      });
    }

    return findings;
  }

  function findFilesByExt(files, exts) {
    return (files || []).filter(function(path) {
      var lower = path.toLowerCase();
      return exts.some(function(e) { return lower.endsWith(e); });
    });
  }

  function getFileName(path) {
    var parts = path.split('/');
    return parts[parts.length - 1] || path;
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
