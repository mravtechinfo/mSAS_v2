/**
 * mSAS v2 — PendingIntent Security Scanner
 * MASTG Ref: MASTG-PLATFORM-8 (PendingIntent Security)
 * CWE-927: Use of Implicit Intent for Communication
 */

var MSAS = MSAS || {};
MSAS.PendingIntentScanner = (function() {
  'use strict';

  var CWE = 'CWE-927';
  var OWASP = 'M1';
  var MASVS = 'PLATFORM-8';

  var PENDING_INTENT_SIGS = [
    'Landroid/app/PendingIntent',
    'PendingIntent',
    'PendingIntent.getActivity',
    'PendingIntent.getService',
    'PendingIntent.getBroadcast',
    'Landroid/app/PendingIntent;->getActivity',
    'Landroid/app/PendingIntent;->getService',
    'Landroid/app/PendingIntent;->getBroadcast'
  ];

  var FLAG_MUTABLE_SIGS = [
    'FLAG_MUTABLE',
    'PendingIntent.FLAG_MUTABLE',
    'PendingIntent.FLAG_IMMUTABLE',
    'FLAG_IMMUTABLE'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasPendingIntent = MSAS.Utils.hasInStrings(strings, PENDING_INTENT_SIGS);
    var hasImmutable = strings.some(function(s) {
      return s.indexOf('FLAG_IMMUTABLE') >= 0 ||
             s.indexOf('PendingIntent.FLAG_IMMUTABLE') >= 0;
    });
    var hasMutable = strings.some(function(s) {
      return s.indexOf('FLAG_MUTABLE') >= 0;
    });

    if (hasPendingIntent) {
      findings.push({
        ruleId: 'mastg-platform-8-pending-intent',
        ruleName: hasImmutable
          ? 'PendingIntent Usage (FLAG_IMMUTABLE)'
          : '⚠️ PendingIntent Usage (No FLAG_IMMUTABLE)',
        severity: hasImmutable ? 'secure' : 'issue',
        description: hasImmutable
          ? 'App uses PendingIntent with FLAG_IMMUTABLE. Since Android 12+, ' +
            'PendingIntents are mutable by default unless FLAG_IMMUTABLE is set. ' +
            'On Android 15+, FLAG_MUTABLE is disallowed for implicit intents.'
          : 'PendingIntent detected without FLAG_IMMUTABLE. On Android 12+, ' +
            'PendingIntents must declare mutability. Mutable PendingIntents can ' +
            'be hijacked by malicious apps to redirect the intent. ' +
            (hasMutable
              ? 'FLAG_MUTABLE is explicitly used. Consider using FLAG_IMMUTABLE ' +
                'if the intent does not need to be modified by the receiver.'
              : 'Consider adding FLAG_IMMUTABLE for PendingIntents unless ' +
                'modification by the target component is required.'),
        cwe: hasImmutable ? '' : CWE,
        owasp: hasImmutable ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'PendingIntent' + (hasImmutable ? ' (immutable)' : ' (mutable or unknown)')
      });
    }

    if (!hasPendingIntent) {
      findings.push({
        ruleId: 'mastg-platform-8-no-pending-intent',
        ruleName: 'No PendingIntent Usage Detected',
        severity: 'secure',
        description: 'No PendingIntent usage detected. If the app uses notifications, ' +
          'alarms, or widget updates, PendingIntent is typically required.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No PendingIntent'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
