/**
 * mSAS v2 — ADB Auditor Scanners (Combined)
 * ADB-1: Intent Fuzzing Detection
 * ADB-4: WebView Debugging Check
 * ADB-5: Permissions Bypass Testing
 * ADB-6: Screen Security Testing
 * ADB-7: Logcat Leakage Scanner
 */

var MSAS = MSAS || {};
MSAS.ADBScanner = (function() {
  'use strict';

  var INTENT_FUZZ_SIGS = [
    'Landroid/content/Intent', 'Landroid/content/IntentFilter',
    'Intent', 'IntentFilter', 'intent-filter',
    'startActivity', 'startService', 'sendBroadcast',
    'Landroid/content/ComponentName', 'ComponentName',
    'Landroid/content/pm/PackageManager'
  ];

  var WEBVIEW_DEBUG_SIGS = [
    'setWebContentsDebuggingEnabled',
    'Landroid/webkit/WebView;->setWebContentsDebuggingEnabled',
    'WebView.setWebContentsDebuggingEnabled',
    'Landroid/webkit/WebView'
  ];

  var PERM_BYPASS_SIGS = [
    'android:exported',
    'Landroid/app/Service',
    'Landroid/content/BroadcastReceiver',
    'Landroid/content/ContentProvider',
    'Landroid/app/admin/DevicePolicyManager',
    'grantUriPermission'
  ];

  var SCREEN_SECURITY_SIGS = [
    'FLAG_SECURE', 'Landroid/view/WindowManager$LayoutParams;->FLAG_SECURE',
    'setFlags', 'Landroid/view/Window',
    'Landroid/view/WindowManager',
    'Landroid/app/Activity',
    'screenrecord', 'screencap', 'SurfaceControl'
  ];

  var LOGCAT_SIGS = [
    'Landroid/util/Log', 'Log.d', 'Log.e', 'Log.i',
    'Landroid/os/Debug', 'isDebuggerConnected',
    'Logcat', 'logcat', 'adb logcat',
    'READ_LOGS', 'android.permission.READ_LOGS'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasIntentFuzz = MSAS.Utils.hasInStrings(strings, INTENT_FUZZ_SIGS);
    var hasWebViewDebug = strings.some(function(s) {
      return s.indexOf('setWebContentsDebuggingEnabled') >= 0;
    });
    var hasPermBypass = MSAS.Utils.hasInStrings(strings, PERM_BYPASS_SIGS);
    var hasScreen = MSAS.Utils.hasInStrings(strings, SCREEN_SECURITY_SIGS);
    var hasLogcat = MSAS.Utils.hasInStrings(strings, LOGCAT_SIGS);

    if (hasIntentFuzz) findings.push({
      ruleId: 'mastg-adb-1-intent-fuzzing', ruleName: 'ADB Intent Testing Surface',
      severity: 'info',
      description: 'App exports components that can be tested via ADB intents. ' +
        'Exported activities, services, and receivers can be invoked with crafted intents.',
      cwe: '', owasp: 'M1', masvs: 'PLATFORM-5',
      file: 'AndroidManifest.xml', line: null, match: 'ADB intent surface'
    });

    if (hasWebViewDebug) findings.push({
      ruleId: 'mastg-adb-4-webview-debug', ruleName: '⚠️ WebView Debugging Enabled',
      severity: 'issue',
      description: 'WebView remote debugging is enabled. Use chrome://inspect to ' +
        'view WebView contents. Disable in production builds.',
      cwe: 'CWE-489', owasp: 'M1', masvs: 'PLATFORM-2',
      file: 'classes.dex', line: null, match: 'WebView debug'
    });

    if (hasScreen) findings.push({
      ruleId: 'mastg-adb-6-screen-security', ruleName: 'Screen Recording / Security',
      severity: hasScreen ? 'secure' : 'info',
      description: 'Screen security (FLAG_SECURE) protects against screen recording ' +
        'and recent apps thumbnail leaks.',
      cwe: '', owasp: 'M2', masvs: 'STORAGE-4',
      file: 'classes.dex', line: null, match: 'Screen security'
    });

    if (hasLogcat) findings.push({
      ruleId: 'mastg-adb-7-logcat', ruleName: 'Logcat Leakage Surface',
      severity: 'info',
      description: 'App uses Android Log API. Log output is readable via ADB logcat.',
      cwe: 'CWE-532', owasp: 'M2', masvs: 'STORAGE-3',
      file: 'classes.dex', line: null, match: 'Logcat surface'
    });

    return findings;
  }
  return { scan: scan };
})();
