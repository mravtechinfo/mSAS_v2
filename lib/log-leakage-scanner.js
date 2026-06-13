/**
 * mSAS v2 — Log Leakage Scanner
 * 
 * Scans APK DEX string pool for Android logging API usage:
 * - android.util.Log class reference
 * - System.out/err print statements
 * - Timber logging library
 * - ProGuard/R8 log stripping assessment
 * - java.util.logging.Logger
 * 
 * MASTG Ref: MASTG-STORAGE-2 (Log Leakage)
 * CWE-532: Insertion of Sensitive Information into Log File
 * 
 * Uses DEX string pool patterns (type descriptors, not Java syntax):
 *   - "Landroid/util/Log;"  — Log class type descriptor
 *   - "Ljava/io/PrintStream;" — System.out type
 *   - "Ltimber/log/Timber;" — Timber type descriptor
 * 
 * Outputs v1-compatible findings: { ruleId, ruleName, severity, description, cwe, owasp, masvs, file, line, match }
 */

var MSAS = MSAS || {};
MSAS.LogLeakageScanner = (function() {
  'use strict';

  var CWE = 'CWE-532';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-2';

  /** Android Log API type descriptor and method references */
  var LOG_CLASS_SIGS = [
    'Landroid/util/Log',
    'Landroid/util/Log;'
  ];

  /** System.out / System.err print stream type descriptor */
  var SYSOUT_SIGS = [
    'Ljava/io/PrintStream'
  ];

  /** Timber logging library */
  var TIMBER_SIGS = [
    'Ltimber/log/Timber',
    'Ltimber/log/Timber;'
  ];

  /** java.util.logging.Logger */
  var LOGGER_SIGS = [
    'Ljava/util/logging/Logger',
    'Ljava/util/logging/Logger;'
  ];

  /** Sensitive data keywords (complementary to engine.js regex) */
  var SENSITIVE_KEYWORDS = [
    'email', 'phone', 'credit_card', 'ssn', 'address',
    'dob', 'birthday', 'cvv', 'pin', 'otp', 'auth',
    'session', 'cookie', 'password', 'secret', 'token'
  ];

  /**
   * Main scan function — produces v1-compatible findings
   */
  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasLogClass    = hasInStrings(strings, LOG_CLASS_SIGS);
    var hasSysOut      = hasInStrings(strings, SYSOUT_SIGS);
    var hasTimber      = hasInStrings(strings, TIMBER_SIGS);
    var hasLogger      = hasInStrings(strings, LOGGER_SIGS);
    var sensitiveRefs  = findSensitiveRefs(strings);

    // 1. Android Log API usage
    if (hasLogClass) {
      var count = countPattern(strings, 'Landroid/util/Log');
      var hasLoggerToo = hasLogger;

      findings.push({
        ruleId: 'mastg-storage-2-log-usage',
        ruleName: 'Android Log API Usage Detected (~' + count + ' references)',
        severity: 'issue',
        description: 'App references the Android Log class (' + count + ' references). ' +
          'Log statements write to logcat, which is accessible to any app with READ_LOGS permission ' +
          'or via ADB. ' +
          (hasLoggerToo ? 'Also uses java.util.logging.Logger which writes to logcat. ' : '') +
          'Ensure no sensitive data (PII, credentials, tokens) is passed to Log methods. ' +
          'Use ProGuard/R8 with -assumenosideeffects to strip Log calls in release builds.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'android.util.Log: ~' + count + ' references' +
               (hasLoggerToo ? ' + java.util.logging.Logger' : '')
      });
    }

    // 2. System.out / System.err usage
    if (hasSysOut) {
      var sysCount = countPattern(strings, 'Ljava/io/PrintStream');
      findings.push({
        ruleId: 'mastg-storage-2-system-out',
        ruleName: 'System.out/System.err Print Statements Detected (~' + sysCount + ')',
        severity: 'issue',
        description: 'App uses System.out/System.err print statements (~' + sysCount + ' references). ' +
          'Unlike android.util.Log, System.out writes to stdout which appears in logcat with no tag ' +
          'or level filtering. These calls persist in release builds unless explicitly removed. ' +
          'On Android, stdout/stderr may be redirected to /dev/null on production devices but remain ' +
          'visible via ADB on debug builds.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'System.out/err: ~' + sysCount + ' references'
      });
    }

    // 3. Timber logging library (positive — good practice)
    if (hasTimber) {
      findings.push({
        ruleId: 'mastg-storage-2-timber',
        ruleName: 'Timber Logging Library Detected',
        severity: 'secure',
        description: 'App uses the Timber logging library, a best practice for Android logging. ' +
          'Timber automatically suppresses verbose/debug logs in release builds when using ' +
          'a ReleaseTree. Verify that Timber.plant(new ReleaseTree()) is called in Application.onCreate() ' +
          'to prevent debug log leakage in production.',
        cwe: '',
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Timber library detected'
      });
    }

    // 4. Sensitive data keywords found alongside logging
    if (sensitiveRefs.length > 0 && (hasLogClass || hasSysOut)) {
      findings.push({
        ruleId: 'mastg-storage-2-sensitive-context',
        ruleName: 'Sensitive Data Keywords in DEX Strings (Log Leakage Risk)',
        severity: 'issue',
        description: 'DEX string pool contains ' + sensitiveRefs.length + ' sensitive data keyword(s): ' +
          sensitiveRefs.join(', ') + '. Combined with ' +
          (hasLogClass ? 'Log API' : '') +
          (hasLogClass && hasSysOut ? ' and ' : '') +
          (hasSysOut ? 'System.out' : '') +
          ' usage, this suggests sensitive data may be written to logs. Review all Log/print calls ' +
          'to ensure sensitive arguments are not passed.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Sensitive keywords: ' + sensitiveRefs.join(', ')
      });
    }

    // 5. No logging detected at all
    if (!hasLogClass && !hasSysOut && !hasTimber && !hasLogger) {
      findings.push({
        ruleId: 'mastg-storage-2-no-logging',
        ruleName: 'No Logging API References Found',
        severity: 'secure',
        description: 'No Android Log API, System.out/err, Timber, or java.util.logging ' +
          'references were found in the DEX string pool. Log statements may have been stripped ' +
          'by ProGuard/R8 obfuscation, or the app does not use logging. Verify this is intentional.',
        cwe: '',
        owasp: OWASP,
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No logging APIs found'
      });
    }

    return findings;
  }

  /**
   * Find sensitive data keywords in DEX strings
   */
  function findSensitiveRefs(strings) {
    var limit = Math.min(strings.length, 50000);
    var found = [];

    for (var si = 0; si < SENSITIVE_KEYWORDS.length; si++) {
      var kw = SENSITIVE_KEYWORDS[si];
      for (var i = 0; i < limit; i++) {
        if (strings[i].toLowerCase().indexOf(kw) >= 0) {
          found.push(kw);
          break;
        }
      }
    }

    return found;
  }

  /**
   * Rough count of pattern occurrences in DEX strings (up to a limit)
   */
  function countPattern(strings, pattern) {
    var limit = Math.min(strings.length, 50000);
    var count = 0;
    for (var i = 0; i < limit; i++) {
      if (strings[i].indexOf(pattern) >= 0) count++;
    }
    return count;
  }

  function findInStrings(strings, signatures) {
    return MSAS.Utils ? MSAS.Utils.findInStrings(strings, signatures) : [];
  }

  function hasInStrings(strings, signatures) {
    return findInStrings(strings, signatures).length > 0;
  }

  return { scan: scan };
})();
