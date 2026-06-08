/**
 * mSAS v2 — Network Security Scanner (NET-3, NET-4)
 * NET-3: Custom Hostname Verifier (MASTG-NETWORK-3)
 * NET-4: Insecure WebSocket Detection (MASTG-NETWORK-1)
 */

var MSAS = MSAS || {};
MSAS.NetworkSecurityScanner = (function() {
  'use strict';

  var HOSTNAME_VERIFIER_SIGS = [
    'Ljavax/net/ssl/HostnameVerifier',
    'Ljavax/net/ssl/HttpsURLConnection;->setHostnameVerifier',
    'Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier',
    'ALLOW_ALL_HOSTNAME_VERIFIER',
    'AllowAllHostnameVerifier',
    'getInsecure'
  ];

  var WEBSOCKET_SIGS = [
    'Lokhttp3/WebSocket',
    'Lokhttp3/WebSocketListener',
    'Lcom/squareup/okhttp3/WebSocket',
    'WebSocket',
    'Ljavax/websocket',
    'Lorg/java_websocket',
    'Socket.IO',
    'io.socket',
    'Lcom/github/nkzawa/socketio',
    'wss://',
    'ws://'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasWeakVerifier = MSAS.Utils.hasInStrings(strings, HOSTNAME_VERIFIER_SIGS);
    var hasWebSocket = MSAS.Utils.hasInStrings(strings, WEBSOCKET_SIGS);
    var hasInsecureWebSocket = strings.some(function(s) {
      return s.indexOf('ws://') >= 0;
    });

    if (hasWeakVerifier) findings.push({
      ruleId: 'mastg-network-3-hostname-verifier',
      ruleName: hasWeakVerifier ? '⚠️ Weak Hostname Verifier' : 'Custom Hostname Verifier',
      severity: 'issue',
      description: 'App uses a custom or permissive HostnameVerifier. ' +
        'ALLOW_ALL_HOSTNAME_VERIFIER accepts any hostname, enabling MITM attacks. ' +
        'Remove custom verifiers and use strict hostname checking.',
      cwe: 'CWE-295', owasp: 'M3', masvs: 'NETWORK-3',
      file: 'classes.dex', line: null, match: 'Weak hostname verifier'
    });

    if (hasWebSocket) {
      findings.push({
        ruleId: 'mastg-network-1-websocket',
        ruleName: hasInsecureWebSocket ? '⚠️ Insecure WebSocket (ws://)' : 'WebSocket Usage Detected',
        severity: hasInsecureWebSocket ? 'issue' : 'info',
        description: hasInsecureWebSocket
          ? 'App uses unencrypted WebSocket connections (ws://). Use wss:// for all ' +
            'WebSocket communication to prevent eavesdropping and tampering.'
          : 'App uses WebSocket connections. Verify all endpoints use wss:// protocol.',
        cwe: hasInsecureWebSocket ? 'CWE-319' : '',
        owasp: hasInsecureWebSocket ? 'M3' : '',
        masvs: 'NETWORK-1',
        file: 'classes.dex', line: null,
        match: hasInsecureWebSocket ? 'Insecure ws://' : 'WebSocket'
      });
    }

    if (!hasWeakVerifier && !hasWebSocket) findings.push({
      ruleId: 'mastg-network-security-clean',
      ruleName: 'No Hostname or WebSocket Issues',
      severity: 'secure',
      description: 'No weak hostname verifiers or WebSocket usage detected.',
      cwe: '', owasp: '', masvs: '',
      file: '', line: null, match: 'Clean'
    });

    return findings;
  }
  return { scan: scan };
})();
