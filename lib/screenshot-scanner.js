/**
 * mSAS v2 — Screenshot Protection Scanner
 * MASTG Ref: MASTG-STORAGE-5 (Screenshot Protection)
 * CWE-200: Exposure of Sensitive Information
 */

var MSAS = MSAS || {};
MSAS.ScreenshotScanner = (function() {
  'use strict';

  var CWE = 'CWE-200';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-5';

  var FLAG_SECURE_SIGS = [
    'FLAG_SECURE',
    'setFlags',
    'WindowManager'
  ];

  var SCREENSHOT_SIGS = [
    'Landroid/media/MediaProjection',
    'createVirtualDisplay',
    'SurfaceView',
    'ImageReader'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasFlagSecure = MSAS.Utils.hasInStrings(strings, ['FLAG_SECURE']);
    var hasWindowFlags = MSAS.Utils.hasInStrings(strings, ['setFlags', 'WindowManager$LayoutParams']);
    var hasScreenshotApi = MSAS.Utils.hasInStrings(strings, SCREENSHOT_SIGS);

    if (hasFlagSecure) {
      findings.push({
        ruleId: 'mastg-storage-5-flag-secure',
        ruleName: 'FLAG_SECURE Detected — Screenshot Protection Enabled',
        severity: 'secure',
        description: 'The app uses WindowManager.LayoutParams.FLAG_SECURE to prevent screenshots ' +
          'and screen recording. This protects sensitive UI content (payment screens, private data) ' +
          'from being captured. FLAG_SECURE also prevents the app from appearing in the recent apps ' +
          'overview/thumbnail. Verify FLAG_SECURE is applied to all sensitive screens/activities.',
        cwe: '',
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'FLAG_SECURE used'
      });
    }

    if (hasScreenshotApi) {
      findings.push({
        ruleId: 'mastg-storage-5-screenshot-api',
        ruleName: 'Screen Capture / MediaProjection API Detected',
        severity: 'issue',
        description: 'App uses MediaProjection or screen capture APIs (createVirtualDisplay, ' +
          'ImageReader). These may capture screen content. On Android 10+, MediaProjection requires ' +
          'user consent via an intent. Verify that captured screen data is not stored or transmitted ' +
          'insecurely.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Screen capture APIs'
      });
    }

    if (!hasFlagSecure && !hasScreenshotApi) {
      findings.push({
        ruleId: 'mastg-storage-5-no-protection',
        ruleName: 'No Screenshot Protection or Capture API Detected',
        severity: 'info',
        description: 'No FLAG_SECURE or MediaProjection APIs were detected. If the app displays ' +
          'sensitive data (financial info, PII, credentials), consider using FLAG_SECURE to prevent ' +
          'screenshots and recent-apps thumbnail leakage.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No screenshot protection'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
