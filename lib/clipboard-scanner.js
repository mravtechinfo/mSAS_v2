/**
 * mSAS v2 — Clipboard Misuse Detection Scanner
 * MASTG Ref: MASTG-STORAGE-3 (Clipboard Data Leakage)
 * CWE-200: Exposure of Sensitive Information
 */

var MSAS = MSAS || {};
MSAS.ClipboardScanner = (function() {
  'use strict';

  var CWE = 'CWE-200';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-3';

  var CLIPBOARD_SIGS = [
    'Landroid/content/ClipboardManager',
    'Landroid/content/ClipData',
    'ClipboardManager',
    'setPrimaryClip',
    'getPrimaryClip'
  ];

  var CLIPBOARD_LISTENER_SIGS = [
    'OnPrimaryClipChangedListener',
    'addPrimaryClipChangedListener'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasClipboard = MSAS.Utils.hasInStrings(strings, CLIPBOARD_SIGS);
    var hasListener = MSAS.Utils.hasInStrings(strings, CLIPBOARD_LISTENER_SIGS);

    if (hasClipboard) {
      findings.push({
        ruleId: 'mastg-storage-3-clipboard-access',
        ruleName: 'Clipboard Access Detected',
        severity: 'issue',
        description: 'App accesses the system clipboard via ClipboardManager API. ' +
          (hasListener ? 'The app also registers a clipboard change listener. ' : '') +
          'Sensitive data (passwords, OTPs, credit card numbers) copied to the clipboard ' +
          'are readable by all apps on Android 9 and below. On Android 10+, clipboard access ' +
          'is restricted but data can still leak via auto-fill or keyboard apps. ' +
          'Avoid copying sensitive data to the clipboard.',
        cwe: CWE,
        owasp: OWASP_M2,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'ClipboardManager API' + (hasListener ? ' + listener' : '')
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-3-no-clipboard',
        ruleName: 'No Clipboard API Usage Detected',
        severity: 'secure',
        description: 'No clipboard access APIs were detected. The app does not interact with the system clipboard.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No clipboard APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
