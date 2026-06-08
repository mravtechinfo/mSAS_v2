/**
 * mSAS v2 — Backup Vulnerability Scanner
 * MASTG Ref: MASTG-STORAGE-7 (Backup Data Leakage)
 * CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
 */

var MSAS = MSAS || {};
MSAS.BackupScanner = (function() {
  'use strict';

  var CWE = 'CWE-530';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-7';

  var ANDROID_BACKUP_SIGS = [
    'Landroid/app/backup/BackupManager',
    'Landroid/app/backup/BackupAgent',
    'Landroid/app/backup/BackupAgentHelper',
    'BackupAgent',
    'BackupManager',
    'SharedPreferencesBackupHelper',
    'FileBackupHelper',
    'Landroid/app/backup/FullBackupDataOutput'
  ];

  var AUTO_BACKUP_SIGS = [
    'android:allowBackup',
    'android:fullBackupContent',
    'android:fullBackupOnly',
    'android:backupAgent'
  ];

  var IOS_BACKUP_SIGS = [
    'NSKeyedArchiver',
    'NSKeyedUnarchiver',
    'NSUserDefaults',
    'UIManagedDocument',
    'NSFileManager',
    'setURLForPublishingUbiquitousItem',
    'NSUbiquitousItem'
  ];

  var NO_BACKUP_FLAG_SIGS = [
    'Landroid/content/Context;->getNoBackupFilesDir',
    'getNoBackupFilesDir',
    'setExcludedFromBackup',
    '.nomedia',
    'NO_BACKUP'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var files = opts.files || [];
    var findings = [];

    var hasBackupAPI = MSAS.Utils.hasInStrings(strings, ANDROID_BACKUP_SIGS);
    var hasAutoBackupRefs = MSAS.Utils.hasInStrings(strings, AUTO_BACKUP_SIGS);
    var hasIosBackup = MSAS.Utils.hasInStrings(strings, IOS_BACKUP_SIGS);
    var hasNoBackupFlag = MSAS.Utils.hasInStrings(strings, NO_BACKUP_FLAG_SIGS);

    // Check manifest files for allowBackup attribute (in XML content from files list)
    var hasManifestAllowBackup = false;
    var hasManifestFullBackup = false;
    for (var i = 0; i < files.length; i++) {
      var fname = files[i].name || files[i];
      if (typeof fname === 'string') {
        if (fname.indexOf('AndroidManifest.xml') >= 0 || fname.indexOf('AndroidManifest') >= 0) {
          // Check if related backup attributes exist in the file content
          // The files array may include content strings for XML files
          var content = (files[i].content || files[i].data || '') + '';
          if (content.indexOf('allowBackup') >= 0 || content.indexOf('fullBackupContent') >= 0) {
            hasManifestAllowBackup = true;
            if (content.indexOf('fullBackupContent') >= 0) hasManifestFullBackup = true;
          }
        }
      }
    }

    // Android backup assessment
    if (hasBackupAPI || hasAutoBackupRefs || hasManifestAllowBackup) {
      var backupDesc = '';
      var backupSeverity = 'issue';

      if (hasNoBackupFlag) {
        backupDesc = 'App uses Android backup APIs and also implements no-backup ' +
          'protections (getNoBackupFilesDir or setExcludedFromBackup). Verify that ' +
          'sensitive files (databases, SharedPreferences, auth tokens) are properly ' +
          'excluded from backup.';
        backupSeverity = 'info';
      } else {
        backupDesc = 'App uses Android backup mechanisms without explicit no-backup ' +
          'protections detected. Backup data can be extracted via ADB (' +
          'adb backup / adb restore). If sensitive data like auth tokens, keys, ' +
          'or credentials are stored in app data, they are included in the backup. ' +
          'Consider excluding sensitive files using getNoBackupFilesDir() or ' +
          'setting android:fullBackupContent to a custom @xml/backup_rules.';
      }

      findings.push({
        ruleId: 'mastg-storage-7-android-backup',
        ruleName: 'Android Backup Mechanisms ' + (hasNoBackupFlag ? '(Protected)' : ''),
        severity: backupSeverity,
        description: backupDesc,
        cwe: hasNoBackupFlag ? '' : CWE,
        owasp: hasNoBackupFlag ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasBackupAPI ? 'BackupManager API' : '') +
          (hasAutoBackupRefs ? (hasBackupAPI ? ' + ' : '') + 'manifest backup attrs' : '') +
          (hasNoBackupFlag ? ' + no-backup protections' : '')
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-7-no-backup',
        ruleName: 'No Android Backup APIs Detected',
        severity: 'info',
        description: 'No explicit Android backup/restore APIs detected. Note that ' +
          'Android automatically backs up app data by default (Auto Backup) ' +
          'since Android 6.0 unless explicitly disabled. Check AndroidManifest.xml ' +
          'for android:allowBackup and android:fullBackupContent attributes.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'Unknown backup state — verify manifest'
      });
    }

    // iOS backup check
    if (hasIosBackup) {
      findings.push({
        ruleId: 'mastg-storage-7-ios-backup',
        ruleName: 'iOS Data Persistence Detected',
        severity: 'info',
        description: 'App uses iOS data persistence mechanisms (NSKeyedArchiver, ' +
          'NSUserDefaults, UIManagedDocument). These may be included in iCloud or ' +
          'iTunes backups. Use NSURL setExcludedFromBackupKey or set ' +
          'NSURLIsExcludedFromBackupKey to protect sensitive files from backup.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'iOS persistence APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
