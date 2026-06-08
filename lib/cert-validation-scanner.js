/**
 * mSAS v2 — Certificate & Signature Validation Scanner
 * MASTG Ref: MASTG-CRYPTO-3 (Certificate Validation) / MASTG-NETWORK-4
 * CWE-295: Improper Certificate Validation
 */

var MSAS = MSAS || {};
MSAS.CertValidationScanner = (function() {
  'use strict';

  var CWE = 'CWE-295';
  var OWASP = 'M3';
  var MASVS = 'NETWORK-4';

  var TRUST_MANAGER_SIGS = [
    'Ljavax/net/ssl/X509TrustManager',
    'Ljavax/net/ssl/TrustManagerFactory',
    'X509TrustManager',
    'checkClientTrusted',
    'checkServerTrusted',
    'getAcceptedIssuers',
    'TrustAllCerts',
    'TrustAllManager',
    'EasyX509TrustManager',
    'NaiveTrustManager'
  ];

  var HOSTNAME_VERIFIER_SIGS = [
    'Ljavax/net/ssl/HostnameVerifier',
    'ALLOW_ALL_HOSTNAME_VERIFIER',
    'SSLSocketFactory',
    'AllowAllHostnameVerifier',
    'Lorg/apache/http/conn/ssl/AllowAllHostnameVerifier'
  ];

  var SSL_CONTEXT_SIGS = [
    'Ljavax/net/ssl/SSLContext',
    'SSLContext',
    'getDefault',
    'setDefault',
    'TLSv1.2',
    'TLSv1.3',
    'keyManager',
    'trustManager',
    'secureRandom'
  ];

  var CUSTOM_TRUST_SIGS = [
    'Ljavax/security/cert/X509Certificate',
    'Ljava/security/cert/CertificateFactory',
    'CertificateFactory',
    'generateCertificate',
    'Ljava/security/cert/CertPathValidator',
    'Ljava/security/cert/CertPathBuilder',
    'Ljava/security/cert/CertStore',
    'PKIXParameters',
    'TrustAnchor',
    'CertPathValidator',
    'CertPathBuilder'
  ];

  var NETWORK_SECURITY_CONFIG_SIGS = [
    'android:networkSecurityConfig',
    'network_security_config',
    '@xml/network_security_config',
    'cleartextTrafficPermitted',
    '@xml/network_security'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasTrustManager = MSAS.Utils.hasInStrings(strings, TRUST_MANAGER_SIGS);
    var hasSSLContext = MSAS.Utils.hasInStrings(strings, SSL_CONTEXT_SIGS);
    var hasCustomTrust = MSAS.Utils.hasInStrings(strings, CUSTOM_TRUST_SIGS);

    // Check for ALLOW_ALL HostnameVerifier specifically
    var hasAllowAll = strings.some(function(s) {
      return s.indexOf('ALLOW_ALL_HOSTNAME_VERIFIER') >= 0 ||
             s.indexOf('AllowAllHostnameVerifier') >= 0 ||
             s.indexOf('getInsecure') >= 0;
    });

    // TrustManager override check
    if (hasTrustManager) {
      var trustSeverity = hasAllowAll ? 'issue' : 'info';

      findings.push({
        ruleId: 'mastg-crypto-3-trust-manager',
        ruleName: hasAllowAll ? '⚠️ Insecure TrustManager Override' : 'Custom TrustManager Detected',
        severity: trustSeverity,
        description: hasAllowAll
          ? 'App uses a weak TrustManager that accepts all certificates (' +
            'ALLOW_ALL_HOSTNAME_VERIFIER, TrustAllCerts, or getInsecure). This makes ' +
            'the app completely vulnerable to man-in-the-middle attacks. Any attacker ' +
            'with network access can intercept and modify all TLS traffic.'
          : 'App implements a custom X509TrustManager. Verify that the implementation ' +
            'properly validates certificate chains and does not accept all certificates. ' +
            'Custom TrustManagers are a common source of MITM vulnerabilities.',
        cwe: hasAllowAll ? CWE : '',
        owasp: hasAllowAll ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasAllowAll ? 'ALLOW_ALL trust' : 'Custom TrustManager'
      });
    }

    // HostnameVerifier check
    if (hasAllowAll) {
      findings.push({
        ruleId: 'mastg-crypto-3-allow-all-verifier',
        ruleName: 'Hostname Verification Disabled',
        severity: 'issue',
        description: 'Hostname verification is disabled (ALLOW_ALL_HOSTNAME_VERIFIER). ' +
          'The app accepts any hostname in TLS certificates, enabling MITM attacks ' +
          'even with valid certificate chains. Remove this and use the default ' +
          'StrictHostnameVerifier.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'ALLOW_ALL_HOSTNAME_VERIFIER'
      });
    }

    // SSLContext configuration check
    if (hasSSLContext) {
      findings.push({
        ruleId: 'mastg-crypto-3-ssl-context',
        ruleName: 'Custom SSLContext Configuration',
        severity: 'info',
        description: 'App configures SSLContext explicitly. Verify that the app uses ' +
          'TLSv1.2+ and does not disable secure protocols. SSLContext.getDefault() ' +
          'on Android 10+ uses reasonable defaults, but custom initialization can ' +
          'introduce vulnerabilities.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'SSLContext usage'
      });
    }

    // Certificate pinning / chain validation check
    if (hasCustomTrust && !hasAllowAll) {
      findings.push({
        ruleId: 'mastg-crypto-3-cert-validation',
        ruleName: 'Certificate Path Validation',
        severity: 'info',
        description: 'App performs custom certificate validation (CertificateFactory, ' +
          'CertPathValidator, PKIX). Verify that certificate chains are validated ' +
          'against trusted CA certificates and that certificate pinning is implemented ' +
          'for critical endpoints.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Custom cert validation'
      });
    }

    // No certificate validation detected
    if (!hasTrustManager && !hasSSLContext && !hasCustomTrust) {
      findings.push({
        ruleId: 'mastg-crypto-3-no-validation',
        ruleName: 'No Custom TLS Certificate Validation',
        severity: 'info',
        description: 'No custom TLS certificate validation was detected. The app likely ' +
          'relies on Android\'s default certificate validation, which uses the system ' +
          'trust store. Verify that the app does not override certificate validation ' +
          'in native code (JNI) or via WebView\'s onReceivedSslError.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'Default TLS validation'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
