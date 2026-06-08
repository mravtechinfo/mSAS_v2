/**
 * mSAS v2 — Service & Broadcast Receiver Audit Scanner
 * MASTG Ref: MASTG-PLATFORM-5 (Component Security)
 * CWE-926: Improper Export of Component
 */

var MSAS = MSAS || {};
MSAS.ComponentsScanner = (function() {
  'use strict';

  var CWE = 'CWE-926';
  var OWASP = 'M1';
  var MASVS = 'PLATFORM-5';

  var SERVICE_SIGS = [
    'Landroid/app/Service',
    'Landroid/app/IntentService',
    'Landroid/app/job/JobService',
    'Landroid/app/job/JobScheduler',
    'startService',
    'stopService',
    'bindService',
    'Landroid/content/ServiceConnection'
  ];

  var BROADCAST_RECEIVER_SIGS = [
    'Landroid/content/BroadcastReceiver',
    'sendBroadcast',
    'sendOrderedBroadcast',
    'sendStickyBroadcast',
    'registerReceiver',
    'unregisterReceiver',
    'LocalBroadcastManager'
  ];

  var EXPORTED_SIGS = [
    'android:exported',
    'exported',
    'Landroid/content/IntentFilter',
    'intent-filter',
    'IntentFilter',
    'addAction',
    'Landroid/content/IntentFilter;->addAction'
  ];

  var STICKY_BROADCAST_SIGS = [
    'sendStickyBroadcast',
    'sendStickyOrderedBroadcast',
    'Landroid/content/Context;->sendStickyBroadcast',
    'Landroid/content/Context;->sendStickyOrderedBroadcast'
  ];

  var DYNAMIC_RECEIVER_SIGS = [
    'registerReceiver',
    'Landroid/content/Context;->registerReceiver',
    'RECEIVER_NOT_EXPORTED',
    'RECEIVER_EXPORTED'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasService = MSAS.Utils.hasInStrings(strings, SERVICE_SIGS);
    var hasReceiver = MSAS.Utils.hasInStrings(strings, BROADCAST_RECEIVER_SIGS);
    var hasExported = MSAS.Utils.hasInStrings(strings, EXPORTED_SIGS);
    var hasSticky = MSAS.Utils.hasInStrings(strings, STICKY_BROADCAST_SIGS);
    var hasDynamicReceiver = MSAS.Utils.hasInStrings(strings, DYNAMIC_RECEIVER_SIGS);

    if (hasService) {
      findings.push({
        ruleId: 'mastg-platform-5-services',
        ruleName: 'Service Components Detected',
        severity: 'info',
        description: 'App uses Service, IntentService, or JobService components. ' +
          'Verify that services are not exported unless required, and that ' +
          'exported services enforce permission checks.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Services'
      });
    }

    if (hasReceiver) {
      var receiverSeverity = hasSticky ? 'issue' : 'info';
      findings.push({
        ruleId: 'mastg-platform-5-broadcast-receivers',
        ruleName: hasSticky
          ? '⚠️ Broadcast Receiver with Sticky Broadcast'
          : 'Broadcast Receiver Components Detected',
        severity: receiverSeverity,
        description: 'App uses BroadcastReceiver components.' +
          (hasSticky
            ? ' ⚠️ Sticky broadcasts are deprecated and accessible to any app. ' +
              'Avoid using sendStickyBroadcast.'
            : '') +
          (hasDynamicReceiver
            ? ' Dynamic receivers detected. On Android 14+, explicitly set ' +
              'RECEIVER_EXPORTED or RECEIVER_NOT_EXPORTED flags.'
            : ''),
        cwe: hasSticky ? CWE : '',
        owasp: hasSticky ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasSticky ? 'Sticky broadcast' : 'Receivers') +
          (hasDynamicReceiver ? ' (dynamic)' : '')
      });
    }

    if (!hasService && !hasReceiver) {
      findings.push({
        ruleId: 'mastg-platform-5-no-components',
        ruleName: 'No Background Components Detected',
        severity: 'info',
        description: 'No Service or BroadcastReceiver components detected. ' +
          'The app may still have activities and content providers ' +
          'for background operations.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No background components'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
