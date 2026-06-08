/**
 * mSAS v2 — PIN / Password Policy Analysis Scanner
 * MASTG Ref: MASTG-AUTH-1 (Password Policy)
 * CWE-521: Weak Password Requirements
 */

var MSAS = MSAS || {};
MSAS.PasswordPolicyScanner = (function() {
  'use strict';

  var CWE = 'CWE-521';
  var OWASP = 'M4';
  var MASVS = 'AUTH-1';

  var PASSWORD_POLICY_SIGS = [
    'passwordLength',
    'minPasswordLength',
    'minLength',
    'setMinLength',
    'PASSWORD_QUALITY',
    'getPasswordQuality',
    'setPasswordQuality',
    'getPasswordMinimumLength',
    'setPasswordMinimumLength',
    'PASSWORD_QUALITY_ALPHABETIC',
    'PASSWORD_QUALITY_ALPHANUMERIC',
    'PASSWORD_QUALITY_NUMERIC',
    'PASSWORD_QUALITY_COMPLEX',
    'PASSWORD_QUALITY_SOMETHING',
    'PASSWORD_QUALITY_UNSPECIFIED',
    'KeyguardManager',
    'isDeviceSecure'
  ];

  var PIN_AUTH_SIGS = [
    'setPin',
    'createPIN',
    'pinAuthentication',
    'authenticateWithPin',
    'LoginActivity',
    'pinEntry',
    'enterPin',
    'pinScreen',
    'checkPin',
    'validatePin'
  ];

  var LOCKOUT_SIGS = [
    'lockout',
    'maxAttempts',
    'MAX_ATTEMPTS',
    'maxRetries',
    'MAX_RETRIES',
    'lockTimer',
    'lockoutTimer',
    'tooManyAttempts',
    'tooManyFailedAttempts',
    'accountLock',
    'AccountLockout',
    'failedAttempts'
  ];

  var STRONG_AUTH_SIGS = [
    'setUserAuthenticationRequired',
    'setUserAuthenticationValidityDuration',
    'setInvalidatedByBiometricEnrollment',
    'BiometricPrompt',
    'Landroidx/biometric/BiometricPrompt',
    'createConfirmDeviceCredentialIntent',
    'confirmCredentials'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasPolicy = MSAS.Utils.hasInStrings(strings, PASSWORD_POLICY_SIGS);
    var hasPinAuth = MSAS.Utils.hasInStrings(strings, PIN_AUTH_SIGS);
    var hasLockout = MSAS.Utils.hasInStrings(strings, LOCKOUT_SIGS);
    var hasStrongAuth = MSAS.Utils.hasInStrings(strings, STRONG_AUTH_SIGS);

    if (hasPinAuth || hasPolicy) {
      findings.push({
        ruleId: 'mastg-auth-1-password-policy',
        ruleName: hasPolicy ? 'Password Policy Implementation' : 'PIN/Authentication Entry Detected',
        severity: hasStrongAuth ? 'secure' : (hasLockout ? 'info' : 'issue'),
        description: hasStrongAuth
          ? 'App implements authentication with strong policy controls including ' +
            'device credential/biometric requirements and lockout mechanisms.'
          : 'App has PIN/password authentication entry points.' +
            (hasPolicy ? ' Password policy APIs detected. Verify that minimum ' +
              'length, complexity requirements, and lockout thresholds are enforced.' : '') +
            (hasLockout ? ' Lockout mechanism detected. Verify account lockout ' +
              'thresholds (5-10 attempts) and lockout duration are configured.' : '') +
            (!hasLockout ? ' No lockout mechanism detected. Implement account ' +
              'lockout after repeated failed attempts to prevent brute-force attacks.' : ''),
        cwe: hasStrongAuth ? '' : CWE,
        owasp: hasStrongAuth ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasPolicy ? 'Password policy' : '') +
          (hasPinAuth ? (hasPolicy ? ' + ' : '') + 'PIN auth' : '') +
          (hasLockout ? ' + lockout' : '') +
          (hasStrongAuth ? ' + strong auth' : '')
      });
    }

    if (!hasPinAuth && !hasPolicy) {
      findings.push({
        ruleId: 'mastg-auth-1-no-auth-entry',
        ruleName: 'No Password/PIN Authentication Entry Detected',
        severity: 'info',
        description: 'No explicit password or PIN authentication entry points detected. ' +
          'If the app requires user authentication, verify that password policies, ' +
          'lockout mechanisms, and secure credential storage are implemented.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No auth entry'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
