/**
 * mSAS v2 — Certificate Pinning Verification Scanner
 * MASTG Ref: MASTG-NETWORK-4 (Certificate Pinning)
 * CWE-295: Improper Certificate Validation
 */

var MSAS = MSAS || {};
MSAS.PinningScanner = (function() {
  'use strict';

  var CWE = 'CWE-295';
  var OWASP = 'M3';
  var MASVS = 'NETWORK-4';

  var OKHTTP_PINNING_SIGS = [
    'Lokhttp3/CertificatePinner',
    'Lokhttp3/OkHttpClient$Builder;->certificatePinner',
    'CertificatePinner',
    'Lcom/squareup/okhttp/CertificatePinner',
    'certificatePinner',
    'pin-sha256',
    'sha256Pin',
    'addSha256Pin'
  ];

  var TRUSTKIT_SIGS = [
    'Lcom/datatheorem/ios/TrustKit',
    'TrustKit',
    'TrustKit.initializeWithNetworkConfiguration',
    'DKAsset',
    'TSKTrustKit'
  ];

  var MANUAL_PINNING_SIGS = [
    'getPublicKey',
    'getEncoded',
    'certificatePinner',
    'pinning'
  ];

  var NSC_PIN_SET_SIGS = [
    'pin-set',
    'pinSet',
    'pin_sha256',
    '<pin>',
    'expiration',
    'network_security_config',
    '@xml/network_security_config'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var files = opts.files || [];
    var findings = [];

    var hasOkHttpPinning = MSAS.Utils.hasInStrings(strings, OKHTTP_PINNING_SIGS);
    var hasTrustKit = MSAS.Utils.hasInStrings(strings, TRUSTKIT_SIGS);
    var hasManualPinning = MSAS.Utils.hasInStrings(strings, MANUAL_PINNING_SIGS);
    var hasNSCPinSet = MSAS.Utils.hasInStrings(strings, NSC_PIN_SET_SIGS);

    var pinningMechanisms = [];
    if (hasOkHttpPinning) pinningMechanisms.push('OkHttp CertificatePinner');
    if (hasTrustKit) pinningMechanisms.push('TrustKit');
    if (hasNSCPinSet) pinningMechanisms.push('Network Security Config pin-set');

    if (pinningMechanisms.length > 0) {
      findings.push({
        ruleId: 'mastg-network-4-pinning-detected',
        ruleName: 'Certificate Pinning Implemented',
        severity: 'secure',
        description: 'Certificate pinning is implemented via ' +
          pinningMechanisms.join(', ') + '. ' +
          'Verify that: (1) pins are for the correct production endpoints, ' +
          '(2) backup pins are configured in case the primary cert is rotated, ' +
          '(3) pin expiration is managed appropriately, ' +
          '(4) pinning does not use OkHttp\'s deprecated certificatePinner ' +
          'on Android 10+ where it is ignored unless domain-level overrides exist.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: pinningMechanisms.join(', ')
      });
    }

    // Manual pinning (less reliable — using certificate comparison in code)
    if (hasManualPinning && pinningMechanisms.length === 0) {
      findings.push({
        ruleId: 'mastg-network-4-manual-pinning',
        ruleName: 'Possible Manual Certificate Pinning',
        severity: 'info',
        description: 'App appears to perform manual certificate validation ' +
          '(public key extraction + hashing + Base64 comparison). This pattern ' +
          'suggests custom certificate pinning logic. Verify that pinning is ' +
          'implemented correctly: check certificate fingerprints, handle cert ' +
          'rotation, and compare against the actual server certificate chain.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Manual pinning pattern'
      });
    }

    // Network Security Config XML check
    if (hasNSCPinSet) {
      findings.push({
        ruleId: 'mastg-network-4-nsc-pins',
        ruleName: 'Network Security Config Pin Set',
        severity: 'info',
        description: 'Network Security Config references pin-set configuration. ' +
          'Verify the @xml/network_security_config file contains proper ' +
          'pin-set entries with SHA-256 hashes and appropriate expiration.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'NSC pin-set'
      });
    }

    if (pinningMechanisms.length === 0 && !hasManualPinning) {
      findings.push({
        ruleId: 'mastg-network-4-no-pinning',
        ruleName: 'No Certificate Pinning Detected',
        severity: 'info',
        description: 'No certificate pinning mechanisms were detected. ' +
          'For apps handling sensitive data or financial transactions, ' +
          'certificate pinning (via OkHttp, TrustKit, or Network Security Config) ' +
          'provides defense-in-depth against CA compromise.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No pinning'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
