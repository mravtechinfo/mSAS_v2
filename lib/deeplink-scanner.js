/**
 * mSAS v2 — Deep Link Validation Scanner
 * MASTG Ref: MASTG-PLATFORM-3 (Deep Link Security)
 * CWE-939: Improper Authorization in Handler for Custom URL Scheme
 */

var MSAS = MSAS || {};
MSAS.DeepLinkScanner = (function() {
  'use strict';

  var CWE = 'CWE-939';
  var OWASP = 'M1';
  var MASVS = 'PLATFORM-3';

  var DEEP_LINK_SIGS = [
    'Landroid/content/Intent',
    'getIntent',
    'getData',
    'getScheme',
    'getHost',
    'getPath',
    'getQueryParameter',
    'getQuery',
    'getDataString'
  ];

  var SCHEME_SIGS = [
    'android:scheme',
    'intent-filter',
    'scheme',
    'host',
    'pathPrefix',
    'pathPattern',
    'autoVerify',
    'android:autoVerify'
  ];

  var INTENT_PARSING_SIGS = [
    'getIntent().getData',
    'getIntent().getScheme',
    'getIntent().getHost',
    'getIntent().getPath',
    'intent.getData',
    'intent.getScheme',
    'intent.getHost',
    'intent.getPath',
    'getIntent().getDataString'
  ];

  var UNVALIDATED_PATTERNS = [
    'getQueryParameter',
    'getStringExtra',
    'getIntExtra',
    'getBooleanExtra'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasSchemes = MSAS.Utils.hasInStrings(strings, SCHEME_SIGS);
    var hasAutoVerify = strings.some(function(s) {
      return s.indexOf('autoVerify') >= 0 ||
             s.indexOf('android:autoVerify') >= 0;
    });

    if (hasSchemes) {
      findings.push({
        ruleId: 'mastg-platform-3-deep-links',
        ruleName: 'Deep Link / URL Scheme Handling Detected',
        severity: hasAutoVerify ? 'secure' : 'issue',
        description: 'App handles custom URL schemes or deep links.' +
          (hasAutoVerify
            ? ' ✅ Android App Links with autoVerify detected for verified domain links.'
            : ' ⚠️ No autoVerify detected. Verify deep link URLs are validated before ' +
              'use to prevent open redirect, SSRF, or authentication bypass. ' +
              'On Android 12+, use android:autoVerify for verified App Links.'),
        cwe: hasAutoVerify ? '' : CWE,
        owasp: hasAutoVerify ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Deep link handling' + (hasAutoVerify ? ' (autoVerify)' : '')
      });
    }

    if (!hasSchemes && !hasDeepLink) {
      findings.push({
        ruleId: 'mastg-platform-3-no-deep-links',
        ruleName: 'No Deep Link Handling Detected',
        severity: 'info',
        description: 'No custom URL scheme or deep link handling detected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No deep links'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
