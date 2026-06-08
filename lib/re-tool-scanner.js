/**
 * mSAS v2 — RE Tool Detection Scanner
 * MASTG Ref: MASTG-RESILIENCE-4 (Reverse Engineering Tools)
 * CWE-693: Protection Mechanism Failure
 */

var MSAS = MSAS || {};
MSAS.REToolScanner = (function() {
  'use strict';

  var CWE = 'CWE-693';
  var OWASP = 'M8';
  var MASVS = 'RESILIENCE-4';

  var FRIDA_SIGS = [
    'frida', 'Frida', 'FRIDA',
    'frida-server', 'fridaserver',
    'LIBFRIDA', 'frida-agent',
    'gum-js-loop', 'g_main_context',
    'FridaScript', 'fridaScript',
    'FridaDetect', 'fridaDetect'
  ];

  var XPOSED_SIGS = [
    'Xposed', 'xposed', 'de.robv.android.xposed',
    'Lde/robv/android/xposed/IXposedHookLoadPackage',
    'Lde/robv/android/xposed/IXposedHookInitPackageResources',
    'XposedBridge', 'xposedbridge',
    'XposedHelpers', 'xposedhelpers',
    'XposedInit', 'xposedInit'
  ];

  var MAGISK_SIGS = [
    'Magisk', 'magisk', 'magiskhide',
    'MagiskHide', 'MagiskManager',
    'su.d', 'magiskpolicy',
    'Lcom/topjohnwu/magisk', 'MagiskSU'
  ];

  var SSL_UNPIN_SIGS = [
    'JustTrustMe', 'SSLUnpin', 'sslunpin',
    'TrustMeAlready', 'NopeSSL',
    'Android-SSL-TrustKiller', 'SSLKiller',
    'Objection', 'objection',
    'patchLg', 'ssl_pinning'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasFrida = MSAS.Utils.hasInStrings(strings, FRIDA_SIGS);
    var hasXposed = MSAS.Utils.hasInStrings(strings, XPOSED_SIGS);
    var hasMagisk = MSAS.Utils.hasInStrings(strings, MAGISK_SIGS);
    var hasSSLUnpin = MSAS.Utils.hasInStrings(strings, SSL_UNPIN_SIGS);

    var tools = [];
    if (hasFrida) tools.push('Frida');
    if (hasXposed) tools.push('Xposed');
    if (hasMagisk) tools.push('Magisk');
    if (hasSSLUnpin) tools.push('SSL unpinning tools');

    if (tools.length > 0) {
      findings.push({
        ruleId: 'mastg-resilience-4-re-tools',
        ruleName: 'RE Tool Detection Implemented',
        severity: 'secure',
        description: 'App implements detection for ' + tools.join(', ') + '. ' +
          'Reverse engineering tools (Frida, Xposed, Magisk) are commonly used ' +
          'for runtime manipulation of apps. Detection helps raise the bar for ' +
          'attackers but can be bypassed.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: tools.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-resilience-4-no-re-tools',
        ruleName: 'No RE Tool Detection',
        severity: 'info',
        description: 'No detection of common reverse engineering tools (Frida, Xposed, ' +
          'Magisk) found. For high-security apps, consider implementing checks against ' +
          'runtime manipulation frameworks.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No RE tool detection'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
