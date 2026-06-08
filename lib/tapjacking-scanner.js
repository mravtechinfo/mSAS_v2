/**
 * mSAS v2 — Tapjacking / Overlay Detection Scanner
 * MASTG Ref: MASTG-PLATFORM-9 (Tapjacking)
 * CWE-1021: Improper Restriction of Rendered UI Layers
 */

var MSAS = MSAS || {};
MSAS.TapjackingScanner = (function() {
  'use strict';

  var CWE = 'CWE-1021';
  var OWASP = 'M1';
  var MASVS = 'PLATFORM-9';

  var TAPJACKING_SIGS = [
    'FLAG_WINDOW_IS_OBSCURED',
    'filterTouchesWhenObscured',
    'setFilterTouchesWhenObscured',
    'onFilterTouchEventForSecurity'
  ];

  var OVERLAY_SIGS = [
    'SYSTEM_ALERT_WINDOW',
    'TYPE_SYSTEM_ALERT',
    'TYPE_APPLICATION_OVERLAY',
    'TYPE_SYSTEM_OVERLAY',
    'Landroid/view/WindowManager;->addView'
  ];

  var DISABLED_FILTER_SIGS = [
    'filterTouchesWhenObscured=\"false\"',
    'filterTouchesWhenObscured=false',
    'setFilterTouchesWhenObscured(false)',
    'setFilterTouchesWhenObscured(false'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasTapjackingProtection = MSAS.Utils.hasInStrings(strings, TAPJACKING_SIGS);
    var hasOverlay = MSAS.Utils.hasInStrings(strings, OVERLAY_SIGS);
    var hasDisabledFilter = MSAS.Utils.hasInStrings(strings, DISABLED_FILTER_SIGS);

    if (hasOverlay) {
      findings.push({
        ruleId: 'mastg-platform-9-overlay-detected',
        ruleName: 'Overlay/SYSTEM_ALERT_WINDOW Detected',
        severity: 'issue',
        description: 'App uses overlay windows (SYSTEM_ALERT_WINDOW, TYPE_APPLICATION_OVERLAY). ' +
          'Malicious apps can draw overlays to steal taps from the app\'s UI. ' +
          (hasTapjackingProtection
            ? ' ✅ Tapjacking protection detected (FLAG_WINDOW_IS_OBSCURED or ' +
              'filterTouchesWhenObscured).'
            : ' ⚠️ No tapjacking protection detected. Use FLAG_WINDOW_IS_OBSCURED or ' +
              'filterTouchesWhenObscured to detect and respond to overlay attacks.'),
        cwe: hasTapjackingProtection ? '' : CWE,
        owasp: hasTapjackingProtection ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Overlay' + (hasTapjackingProtection ? ' + protection' : '')
      });
    }

    if (hasDisabledFilter) {
      findings.push({
        ruleId: 'mastg-platform-9-filter-disabled',
        ruleName: 'Tapjacking Protection Explicitly Disabled',
        severity: 'issue',
        description: 'filterTouchesWhenObscured is explicitly set to false. ' +
          'The app will not detect overlay-based tapjacking attacks. ' +
          'Remove this setting or set it to true to enable protection.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'filterTouchesWhenObscured=false'
      });
    }

    if (!hasOverlay && !hasTapjackingProtection) {
      findings.push({
        ruleId: 'mastg-platform-9-no-overlay',
        ruleName: 'No Overlay or Tapjacking Protection Detected',
        severity: 'info',
        description: 'No overlay permissions or tapjacking protection detected. ' +
          'For apps handling sensitive data, consider using ' +
          'filterTouchesWhenObscured=true to defend against overlay attacks.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No overlay'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
