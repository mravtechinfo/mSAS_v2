/**
 * mSAS v2 — Scoped Storage Audit Scanner
 * MASTG Ref: MASTG-STORAGE-1 (Local Data Storage)
 * CWE-921: Storage of Sensitive Data in a Mechanism without Access Control
 */

var MSAS = MSAS || {};
MSAS.ScopedStorageScanner = (function() {
  'use strict';

  var CWE = 'CWE-921';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-1';

  var LEGACY_STORAGE_SIGS = [
    'Landroid/os/Environment;->getExternalStorageDirectory',
    'Landroid/os/Environment;->getExternalStoragePublicDirectory',
    'getExternalStorageDirectory',
    'getExternalStoragePublicDirectory',
    'WRITE_EXTERNAL_STORAGE',
    'READ_EXTERNAL_STORAGE',
    '/sdcard/',
    '/mnt/sdcard/',
    '/storage/emulated/'
  ];

  var MANAGE_STORAGE_SIGS = [
    'MANAGE_EXTERNAL_STORAGE',
    'android.permission.MANAGE_EXTERNAL_STORAGE',
    'ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION',
    'isExternalStorageManager',
    'Landroid/os/Environment;->isExternalStorageManager'
  ];

  var MEDIA_STORE_SIGS = [
    'Landroid/provider/MediaStore',
    'MediaStore',
    'ContentResolver',
    'Landroid/provider/MediaStore$Images$Media',
    'Landroid/provider/MediaStore$Video$Media',
    'Landroid/provider/MediaStore$Audio$Media'
  ];

  var SAF_SIGS = [
    'Landroid/content/Intent;->ACTION_OPEN_DOCUMENT',
    'ACTION_OPEN_DOCUMENT',
    'ACTION_CREATE_DOCUMENT',
    'ACTION_OPEN_DOCUMENT_TREE',
    'Landroid/provider/DocumentsContract',
    'DocumentsContract',
    'StorageAccessFramework'
  ];

  var INTERNAL_STORAGE_SIGS = [
    'openFileOutput',
    'Landroid/content/Context;->openFileOutput',
    'getFilesDir',
    'Landroid/content/Context;->getFilesDir',
    'getDir',
    'Ljava/io/FileOutputStream',
    'Ljava/io/FileWriter'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasLegacyStorage = MSAS.Utils.hasInStrings(strings, LEGACY_STORAGE_SIGS);
    var hasManageStorage = MSAS.Utils.hasInStrings(strings, MANAGE_STORAGE_SIGS);
    var hasMediaStore = MSAS.Utils.hasInStrings(strings, MEDIA_STORE_SIGS);
    var hasSAF = MSAS.Utils.hasInStrings(strings, SAF_SIGS);
    var hasInternalStorage = MSAS.Utils.hasInStrings(strings, INTERNAL_STORAGE_SIGS);

    // Legacy external storage
    if (hasLegacyStorage) {
      findings.push({
        ruleId: 'mastg-storage-1-legacy-external-storage',
        ruleName: 'Legacy External Storage Access Detected',
        severity: 'issue',
        description: 'App uses legacy external storage APIs (getExternalStorageDirectory, ' +
          'WRITE_EXTERNAL_STORAGE). Files written to these locations are accessible by ' +
          'other apps with storage permissions. ' +
          'On Android 10+, scoped storage restricts direct file path access. ' +
          'Migrate to MediaStore API, Storage Access Framework (SAF), or app-specific ' +
          'getExternalFilesDir(). ' +
          (hasManageStorage
            ? '⚠️ App also requests MANAGE_EXTERNAL_STORAGE — this broad permission ' +
              'allows access to all files on external storage and requires special ' +
              'Google Play approval. Only legitimate file managers or antivirus apps ' +
              'should use this.'
            : ''),
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Legacy external storage' +
          (hasManageStorage ? ' + MANAGE_EXTERNAL_STORAGE' : '')
      });
    }

    // MANAGE_EXTERNAL_STORAGE permission
    if (hasManageStorage && !hasLegacyStorage) {
      findings.push({
        ruleId: 'mastg-storage-1-manage-storage-permission',
        ruleName: 'MANAGE_EXTERNAL_STORAGE Permission',
        severity: 'issue',
        description: 'App requests MANAGE_EXTERNAL_STORAGE permission. This is a ' +
          'high-risk permission that grants broad file access. It requires Google ' +
          'Play approval and should only be used by file managers, backup tools, ' +
          'or antivirus apps. Most apps should use SAF or MediaStore instead.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'AndroidManifest.xml',
        line: null,
        match: 'MANAGE_EXTERNAL_STORAGE'
      });
    }

    // Modern storage approach assessment
    var modernApproach = hasMediaStore || hasSAF;
    var hasAnyExternal = hasLegacyStorage || hasManageStorage || hasMediaStore || hasSAF;

    if (modernApproach) {
      findings.push({
        ruleId: 'mastg-storage-1-modern-storage',
        ruleName: 'Modern Storage API Detected',
        severity: 'secure',
        description: 'App uses modern storage APIs (' +
          (hasMediaStore ? 'MediaStore' : '') +
          (hasMediaStore && hasSAF ? ' and ' : '') +
          (hasSAF ? 'Storage Access Framework' : '') +
          '). These are scoped-storage-compatible APIs that provide better data ' +
          'isolation compared to legacy file path access.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasMediaStore ? 'MediaStore' : '') +
          (hasMediaStore && hasSAF ? ' + ' : '') +
          (hasSAF ? 'SAF' : '')
      });
    }

    // Internal storage summary
    if (hasInternalStorage) {
      findings.push({
        ruleId: 'mastg-storage-1-internal-storage',
        ruleName: 'Internal Storage Usage Detected',
        severity: 'info',
        description: 'App writes files to internal storage (openFileOutput, getFilesDir). ' +
          'Internal storage is sandboxed per app and not accessible by other apps ' +
          'without root. Verify that files are created with MODE_PRIVATE (not ' +
          'MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE) and that sensitive data ' +
          'stored internally is encrypted.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Internal storage APIs'
      });
    }

    // No storage detected
    if (!hasAnyExternal && !hasInternalStorage) {
      findings.push({
        ruleId: 'mastg-storage-1-no-storage',
        ruleName: 'No File Storage APIs Detected',
        severity: 'info',
        description: 'No explicit file storage APIs detected. The app may store data ' +
          'via SharedPreferences, databases, or network-only. Verify that any ' +
          'persisted data is properly protected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No storage APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
