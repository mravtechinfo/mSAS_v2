/**
 * mSAS v2 — TLS Configuration Audit Scanner
 * MASTG Ref: MASTG-NETWORK-2 (TLS Protocol Configuration)
 * CWE-326: Inadequate Encryption Strength
 */

var MSAS = MSAS || {};
MSAS.TlsConfigScanner = (function() {
  'use strict';

  var CWE = 'CWE-326';
  var OWASP = 'M3';
  var MASVS = 'NETWORK-2';

  var TLS_VERSIONS_SIGS = [
    'TLSv1.3',
    'TLSv1.2',
    'TLS',
    'TLSv1.1',
    'TLSv1',
    'SSLv3',
    'SSLv2',
    'SSL'
  ];

  var SSL_CONTEXT_SIGS = [
    'Ljavax/net/ssl/SSLContext',
    'SSLContext.getInstance',
    'SSLContext.getDefault',
    'SSLContext.setDefault'
  ];

  var TLS_LAYER_SIGS = [
    'Ljavax/net/ssl/SSLSocket',
    'Ljavax/net/ssl/SSLSocketFactory',
    'Ljavax/net/ssl/SSLServerSocket',
    'SSLSocket',
    'SSLSocketFactory',
    'setEnabledProtocols',
    'setEnabledCipherSuites',
    'getEnabledProtocols',
    'getSupportedProtocols'
  ];

  var WEAK_TLS_SIGS = [
    'SSLContext.getInstance("SSL"',
    'SSLContext.getInstance("TLS"',
    'SSLContext.getInstance("TLSv1.1"',
    'SSLContext.getInstance("TLSv1"'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasSSLContext = MSAS.Utils.hasInStrings(strings, SSL_CONTEXT_SIGS);
    var hasTLSLayer = MSAS.Utils.hasInStrings(strings, TLS_LAYER_SIGS);
    var hasTLS = MSAS.Utils.hasInStrings(strings, TLS_VERSIONS_SIGS);

    var hasWeakTLS = strings.some(function(s) {
      return s.indexOf('SSLContext.getInstance("SSL"') >= 0 ||
             s.indexOf("SSLContext.getInstance('SSL'") >= 0 ||
             s.indexOf('SSLSocketFactory.getDefault') >= 0;
    });

    var hasTLS13 = strings.some(function(s) {
      return s.indexOf('TLSv1.3') >= 0 || s.indexOf('TLS 1.3') >= 0;
    });

    if (hasSSLContext || hasTLSLayer) {
      var secLevel = hasWeakTLS ? 'issue' : (hasTLS13 ? 'secure' : 'info');

      findings.push({
        ruleId: 'mastg-network-2-tls-config',
        ruleName: hasWeakTLS
          ? '⚠️ Weak TLS/SSL Protocol Configuration'
          : 'TLS Configuration' + (hasTLS13 ? ' (TLS 1.3 Capable)' : ''),
        severity: secLevel,
        description: hasWeakTLS
          ? 'App uses weak TLS/SSL configuration (SSLContext SSL/TLS, or ' +
            'SSLSocketFactory.getDefault). Android 10+ defaults to TLSv1.2+, but ' +
            'explicitly setting insecure protocols reduces security. Use ' +
            'SSLContext.getInstance("TLSv1.3") or rely on system defaults.'
          : 'App configures TLS connections explicitly.' +
            (hasTLS13
              ? ' ✅ TLSv1.3 support detected — the most current and secure TLS version.'
              : ' Verify that minimum TLS version is set to TLSv1.2 and weak ' +
                'cipher suites are disabled using setEnabledProtocols.'),
        cwe: hasWeakTLS ? CWE : '',
        owasp: hasWeakTLS ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasWeakTLS ? 'Weak TLS config' : (hasTLS13 ? 'TLS 1.3' : 'TLS config')
      });
    }

    if (!hasSSLContext && !hasTLSLayer) {
      findings.push({
        ruleId: 'mastg-network-2-no-tls-config',
        ruleName: 'No Custom TLS Configuration',
        severity: 'info',
        description: 'No explicit TLS configuration detected. The app relies on ' +
          'Android system defaults for HTTPS connections. Android 10+ uses ' +
          'TLSv1.2+ by default, which is secure.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'Default TLS'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
