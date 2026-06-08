/**
 * mSAS v2 — Cleartext Traffic Analysis Scanner
 * MASTG Ref: MASTG-NETWORK-1 (Cleartext Network Traffic)
 * CWE-319: Cleartext Transmission of Sensitive Information
 */

var MSAS = MSAS || {};
MSAS.CleartextScanner = (function() {
  'use strict';

  var CWE = 'CWE-319';
  var OWASP = 'M3';
  var MASVS = 'NETWORK-1';

  var HTTP_URL_SIGS = [
    'http://',
    'HTTP://',
    'HttpURLConnection',
    'Ljavax/net/ssl/HttpsURLConnection',
    'Landroid/net/http/AndroidHttpClient',
    'DefaultHttpClient',
    'Lorg/apache/http/impl/client/DefaultHttpClient',
    'HttpClient',
    'Lorg/apache/http/client/HttpClient'
  ];

  var WEBSOCKET_SIGS = [
    'Lokhttp3/WebSocket',
    'Lokhttp3/OkHttpClient',
    'Lcom/squareup/okhttp3/WebSocket',
    'WebSocket',
    'Ljavax/websocket',
    'okhttp3.internal.ws',
    'WebSocketListener'
  ];

  var CLEARTEXT_NSC_SIGS = [
    'cleartextTrafficPermitted',
    'usesCleartextTraffic',
    '@xml/network_security_config',
    'network_security_config',
    'android:usesCleartextTraffic'
  ];

  var LOCALHOST_HTTP_SIGS = [
    'http://localhost',
    'http://127.0.0.1',
    'http://10.0.2.2',
    'http://192.168'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasHttp = MSAS.Utils.hasInStrings(strings, HTTP_URL_SIGS);
    var hasWebSocket = MSAS.Utils.hasInStrings(strings, WEBSOCKET_SIGS);
    var hasCleartextConfig = MSAS.Utils.hasInStrings(strings, CLEARTEXT_NSC_SIGS);
    var hasLocalhostHttp = MSAS.Utils.hasInStrings(strings, LOCALHOST_HTTP_SIGS);

    // Look for explicit http:// URLs in DEX strings
    var explicitHttpUrls = strings.filter(function(s) {
      return s.indexOf('http://') >= 0 &&
             s.indexOf('http://localhost') < 0 &&
             s.indexOf('http://127.0.0.1') < 0 &&
             s.indexOf('http://10.0.2.2') < 0;
    }).slice(0, 5);

    if (hasHttp || explicitHttpUrls.length > 0) {
      var isPureHttp = explicitHttpUrls.length > 0 &&
        !strings.some(function(s) { return s.indexOf('https://') >= 0; });

      findings.push({
        ruleId: 'mastg-network-1-cleartext-http',
        ruleName: isPureHttp ? '⚠️ Cleartext HTTP Only (No HTTPS)' : 'HTTP URLs Detected',
        severity: isPureHttp ? 'issue' : 'info',
        description: isPureHttp
          ? 'The app uses HTTP URLs without any HTTPS references found. All network ' +
            'traffic is sent in cleartext. This means all data (passwords, tokens, API ' +
            'responses) is visible to any attacker on the same network.'
          : 'App uses HTTP connections. ' +
            (explicitHttpUrls.length > 0
              ? 'Found ' + explicitHttpUrls.length + ' explicit http:// URL' +
                (explicitHttpUrls.length > 1 ? 's' : '') + ' in DEX strings.'
              : 'Legacy HTTP APIs detected (HttpURLConnection, HttpClient).') +
            ' Verify that sensitive endpoints use HTTPS and cleartext traffic is not ' +
            'enabled in network_security_config.xml.',
        cwe: isPureHttp ? CWE : '',
        owasp: isPureHttp ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: isPureHttp ? 'HTTP only (no HTTPS)' :
          (explicitHttpUrls.length > 0 ? explicitHttpUrls.slice(0, 3).join('; ') : 'HTTP API usage')
      });
    } else {
      findings.push({
        ruleId: 'mastg-network-1-no-cleartext',
        ruleName: 'No Cleartext HTTP Detected',
        severity: 'secure',
        description: 'No cleartext HTTP URLs or plain HTTP API usage detected. ' +
          'The app appears to use HTTPS for network communication.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No HTTP detected'
      });
    }

    // WebSocket detection
    if (hasWebSocket) {
      findings.push({
        ruleId: 'mastg-network-1-websocket',
        ruleName: 'WebSocket Usage Detected',
        severity: 'info',
        description: 'App uses WebSocket connections. Verify that WebSocket ' +
          'connections use secure wss:// protocol, not unencrypted ws://.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'WebSocket detected'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
