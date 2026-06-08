/**
 * mSAS v2 — WebView Security Audit Scanner
 * MASTG Ref: MASTG-PLATFORM-1/2 (WebView Security)
 * CWE-749: Exposed Dangerous Method
 */

var MSAS = MSAS || {};
MSAS.WebViewScanner = (function() {
  'use strict';

  var CWE = 'CWE-749';
  var OWASP = 'M7';
  var MASVS = 'PLATFORM-1';

  var WEBVIEW_SIGS = [
    'Landroid/webkit/WebView',
    'Landroid/webkit/WebSettings',
    'Landroid/webkit/WebChromeClient',
    'Landroid/webkit/WebViewClient',
    'WebView',
    'getSettings',
    'loadUrl',
    'loadData',
    'evaluateJavascript'
  ];

  var JS_SIGS = [
    'setJavaScriptEnabled',
    'javaScriptEnabled',
    'getSettings',
    'Landroid/webkit/WebSettings;->setJavaScriptEnabled'
  ];

  var JSI_SIGS = [
    'addJavascriptInterface',
    'Landroid/webkit/WebView;->addJavascriptInterface',
    'JavascriptInterface',
    'Landroid/webkit/JavascriptInterface'
  ];

  var FILE_ACCESS_SIGS = [
    'setAllowFileAccess',
    'setAllowFileAccessFromFileURLs',
    'setAllowUniversalAccessFromFileURLs',
    'setAllowContentAccess',
    'setAllowFileAccess',
    'file://',
    'file:///android_asset',
    'file:///android_res'
  ];

  var DEBUG_SIGS = [
    'setWebContentsDebuggingEnabled',
    'WebView.setWebContentsDebuggingEnabled',
    'Landroid/webkit/WebView;->setWebContentsDebuggingEnabled'
  ];

  var SSL_HANDLER_SIGS = [
    'onReceivedSslError',
    'Landroid/webkit/WebViewClient;->onReceivedSslError',
    'proceed',
    'handler.proceed',
    'SslErrorHandler'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasWebView = MSAS.Utils.hasInStrings(strings, WEBVIEW_SIGS);
    var hasJS = MSAS.Utils.hasInStrings(strings, JS_SIGS);
    var hasJSI = MSAS.Utils.hasInStrings(strings, JSI_SIGS);
    var hasFileAccess = MSAS.Utils.hasInStrings(strings, FILE_ACCESS_SIGS);
    var hasDebug = MSAS.Utils.hasInStrings(strings, DEBUG_SIGS);
    var hasSSLOverride = MSAS.Utils.hasInStrings(strings, SSL_HANDLER_SIGS);

    if (!hasWebView) {
      findings.push({
        ruleId: 'mastg-platform-1-no-webview',
        ruleName: 'No WebView Usage Detected',
        severity: 'secure',
        description: 'No WebView usage detected in the application.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No WebView'
      });
      return findings;
    }

    var riskCount = 0;
    var risks = [];

    if (hasJS) { riskCount++; risks.push('JavaScript enabled'); }
    if (hasJSI) { riskCount++; risks.push('JavaScriptInterface'); }
    if (hasFileAccess) { riskCount++; risks.push('file access enabled'); }
    if (hasDebug) { riskCount++; risks.push('debugging enabled'); }
    if (hasSSLOverride) { riskCount++; risks.push('SSL error override'); }

    if (hasJS || hasJSI || hasFileAccess || hasDebug || hasSSLOverride) {
      findings.push({
        ruleId: 'mastg-platform-1-webview-risks',
        ruleName: 'WebView Security Risk' + (riskCount > 1 ? 's' : '') + ' Detected',
        severity: (hasJSI || hasDebug) ? 'issue' : 'info',
        description: 'WebView detected with ' + riskCount + ' risk' +
          (riskCount > 1 ? 's' : '') + ': ' + risks.join(', ') + '. ' +
          (hasJSI ? '⚠️ addJavascriptInterface exposes Java methods to JavaScript ' +
            'and enables RCE on Android < 4.2. Use @JavascriptInterface annotation.' : '') +
          (hasDebug ? ' ⚠️ WebView debugging should be disabled in production.' : '') +
          (hasJS ? ' Verify JavaScript is required for functionality.' : ''),
        cwe: (hasJSI || hasDebug) ? CWE : '',
        owasp: (hasJSI || hasDebug) ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: risks.join(', ')
      });
    }

    return findings;
  }

  return { scan: scan };
})();
