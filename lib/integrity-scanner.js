/**
 * mSAS v2 — Runtime Integrity Verification Scanner
 * MASTG Ref: MASTG-RESILIENCE-3 (Integrity Verification)
 * CWE-353: Missing Integrity Check
 */

var MSAS = MSAS || {};
MSAS.IntegrityScanner = (function() {
  'use strict';

  var CWE = 'CWE-353';
  var OWASP = 'M8';
  var MASVS = 'RESILIENCE-3';

  var SIGNATURE_SIGS = [
    'Landroid/content/pm/PackageManager;->GET_SIGNATURES',
    'Landroid/content/pm/Signature',
    'getPackageManager',
    'getPackageInfo',
    'PackageManager.GET_SIGNATURES',
    'signatures',
    'signingInfo',
    'getSigningInfo',
    'Landroid/content/pm/PackageManager;->getPackageInfo'
  ];

  var HASH_SIGS = [
    'MessageDigest',
    'digest',
    'signature',
    'checksum',
    'CRC32',
    'Adler32'
  ];

  var PLAY_INTEGRITY_SIGS = [
    'PlayIntegrity',
    'Lcom/google/android/play/core/integrity',
    'IntegrityManager',
    'IntegrityTokenResponse',
    'SafetyNet',
    'Lcom/google/android/gms/safetynet',
    'SafetyNetApi',
    'attestation',
    'attestationNonce',
    'GoogleApiAvailability'
  ];

  var CERT_SIGS = [
    'X509Certificate',
    'getPublicKey',
    'getEncoded',
    'CertificateFactory',
    'generateCertificate',
    'Ljava/security/cert/CertificateFactory',
    'Ljava/security/MessageDigest'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasSignature = MSAS.Utils.hasInStrings(strings, SIGNATURE_SIGS);
    var hasHash = MSAS.Utils.hasInStrings(strings, HASH_SIGS);
    var hasPlayIntegrity = MSAS.Utils.hasInStrings(strings, PLAY_INTEGRITY_SIGS);
    var hasCert = MSAS.Utils.hasInStrings(strings, CERT_SIGS);

    if (hasPlayIntegrity) {
      findings.push({
        ruleId: 'mastg-resilience-3-play-integrity',
        ruleName: 'Play Integrity / SafetyNet Attestation',
        severity: 'secure',
        description: 'App uses Play Integrity or SafetyNet attestation to verify ' +
          'device integrity. This helps detect rooted devices, custom ROMs, ' +
          'and tampered app installations.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Play Integrity / SafetyNet'
      });
    }

    if (hasSignature || hasCert) {
      findings.push({
        ruleId: 'mastg-resilience-3-signature-check',
        ruleName: hasSignature ? 'APK Signature Verification' : 'Certificate Validation Detected',
        severity: hasPlayIntegrity ? 'secure' : 'info',
        description: 'App verifies its own APK signature or validates certificates. ' +
          'This helps detect repackaged or tampered APKs.' +
          (hasPlayIntegrity
            ? ''
            : ' Consider supplementing with Play Integrity API for stronger guarantees.'),
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasSignature ? 'Signature check' : '') +
          (hasCert ? (hasSignature ? ' + ' : '') + 'cert validation' : '')
      });
    }

    if (!hasPlayIntegrity && !hasSignature && !hasCert) {
      findings.push({
        ruleId: 'mastg-resilience-3-no-integrity',
        ruleName: 'No App Integrity Verification',
        severity: 'info',
        description: 'No app integrity, signature, or attestation checks detected. ' +
          'Consider implementing signature verification or Play Integrity API ' +
          'to detect repackaged or tampered APKs.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No integrity checks'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
