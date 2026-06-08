/**
 * mSAS v2 — Code Quality Scanners (Combined)
 * COD-2: Debug Symbols Check (MASTG-CODE-1)
 * COD-5: Insecure Update Detection (MASTG-CODE-8)
 * COD-10: Exact Alarm & Background Check (MASTG-CODE-9)
 */

var MSAS = MSAS || {};
MSAS.CodeQualityScanner = (function() {
  'use strict';

  var DEBUG_SYMBOLS_SIGS = [
    'debuggable', 'android:debuggable', 'debuggable=true',
    'isDebug', 'BuildConfig.DEBUG', 'DEBUG_MODE',
    'dSYM', 'dsym', 'DWARF',
    'android:debug', 'debugBuild'
  ];

  var INSECURE_UPDATE_SIGS = [
    'inAppUpdate', 'in_app_update', 'InAppUpdate',
    'Lcom/google/android/play/core/appupdate',
    'updateUrl', 'update_url', 'UPDATE_URL',
    'checkForUpdate', 'downloadUpdate', 'installUpdate',
    'Landroid/app/DownloadManager', 'Landroid/content/Context;->getSystemService',
    'Lcom/amazon/device/iap',
    'Lorg/apache/http/impl/client/DefaultHttpClient'
  ];

  var EXACT_ALARM_SIGS = [
    'setExact', 'Landroid/app/AlarmManager;->setExact',
    'setExactAndAllowWhileIdle', 'setAlarmClock',
    'SCHEDULE_EXACT_ALARM', 'USE_EXACT_ALARM',
    'Landroid/app/AlarmManager', 'AlarmManager',
    'Landroid/app/PendingIntent',
    'WorkManager', 'Landroidx/work/WorkManager',
    'PeriodicWorkRequest', 'Landroidx/work/PeriodicWorkRequest'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasDebugSymbols = MSAS.Utils.hasInStrings(strings, DEBUG_SYMBOLS_SIGS);
    var hasInsecureUpdate = MSAS.Utils.hasInStrings(strings, INSECURE_UPDATE_SIGS);
    var hasExactAlarm = MSAS.Utils.hasInStrings(strings, EXACT_ALARM_SIGS);

    if (hasDebugSymbols) findings.push({
      ruleId: 'mastg-code-1-debug-symbols', ruleName: 'Debug Mode / Symbols Detected',
      severity: 'issue',
      description: 'App may include debug symbols or debuggable flags. ' +
        'Debug builds should never be distributed. Remove debug artifacts from release builds.',
      cwe: 'CWE-489', owasp: 'M9', masvs: 'CODE-1',
      file: 'classes.dex', line: null, match: 'Debug symbols'
    });

    if (hasInsecureUpdate) findings.push({
      ruleId: 'mastg-code-8-insecure-update', ruleName: 'In-App Update Mechanism Detected',
      severity: 'info',
      description: 'App has update checking logic. Verify the update URL uses HTTPS ' +
        'and that update integrity is verified via cryptographic signing. ' +
        'For Android, use Play Core In-app updates API.',
      cwe: 'CWE-494', owasp: 'M7', masvs: 'CODE-8',
      file: 'classes.dex', line: null, match: 'In-app update'
    });

    if (hasExactAlarm) findings.push({
      ruleId: 'mastg-code-9-exact-alarm', ruleName: 'Exact Alarm / WorkManager Detected',
      severity: 'info',
      description: 'App schedules exact alarms or uses WorkManager for background tasks. ' +
        'On Android 12+, SCHEDULE_EXACT_ALARM requires user grant. ' +
        'Verify background tasks respect Doze mode and battery optimization.',
      cwe: '', owasp: '', masvs: 'CODE-9',
      file: 'classes.dex', line: null, match: 'Alarms/WorkManager'
    });

    if (!hasDebugSymbols && !hasInsecureUpdate && !hasExactAlarm) findings.push({
      ruleId: 'mastg-code-quality-none', ruleName: 'No Code Quality Issues Detected',
      severity: 'secure',
      description: 'No debug symbols, insecure update mechanisms, or alarm scheduling detected.',
      cwe: '', owasp: '', masvs: '',
      file: '', line: null, match: 'Clean'
    });

    return findings;
  }
  return { scan: scan };
})();
