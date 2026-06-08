/**
 * mSAS v2 — Local Authentication Bypass Detection Scanner
 * MASTG Ref: MASTG-AUTH-8 (Local Authentication Bypass)
 * CWE-287: Improper Authentication
 */

var MSAS = MSAS || {};
MSAS.AuthBypassScanner = (function() {
  'use strict';

  var CWE = 'CWE-287';
  var OWASP = 'M4';
  var MASVS = 'AUTH-8';

  var AUTH_STATE_SIGS = [
    'isAuthenticated',
    'IS_AUTHENTICATED',
    'isLoggedIn',
    'is_logged_in',
    'getIsAuthenticated',
    'setIsAuthenticated',
    'isAuth',
    'hasAuth',
    'authenticated',
    'AUTHENTICATED',
    'isAuthorized',
    'hasAccess',
    'grantAccess',
    'setAuthentication',
    'authenticate'
  ];

  var BYPASS_SIGS = [
    'BYPASS',
    'bypass',
    'disableAuth',
    'disableAuthentication',
    'skipAuth',
    'bypassAuth',
    'enableDebug',
    'debugMode',
    'ALLOW_ALL',
    'allowAll',
    'trustAll',
    'TrustAll'
  ];

  var ROOT_BYPASS_SIGS = [
    'isRooted',
    'isDeviceRooted',
    'RootBeer',
    'rootDetection',
    'isRootDetection',
    'rootCheck',
    'checkRoot',
    'skipRootCheck',
    'disableRootDetection',
    'rootBypass',
    'RootCloak',
    'MagiskHide'
  ];

  var DEBUG_BYPASS_SIGS = [
    'isDebuggerConnected',
    'isDebug',
    'BuildConfig.DEBUG',
    'debuggable',
    'setDebuggable',
    'DEBUG_MODE',
    'isDebuggable',
    'enableDebugMode',
    'disableSecurity'
  ];

  var INTEGRITY_BYPASS_SIGS = [
    'SafetyNet',
    'PlayIntegrity',
    'integrityCheck',
    'verifyIntegrity',
    'integrity',
    'checkIntegrity',
    'skipIntegrity',
    'bypassIntegrity',
    'integrityResult',
    'attestation'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasAuthState = MSAS.Utils.hasInStrings(strings, AUTH_STATE_SIGS);
    var hasBypass = MSAS.Utils.hasInStrings(strings, BYPASS_SIGS);
    var hasRootBypass = MSAS.Utils.hasInStrings(strings, ROOT_BYPASS_SIGS);
    var hasDebugBypass = MSAS.Utils.hasInStrings(strings, DEBUG_BYPASS_SIGS);
    var hasIntegrityBypass = MSAS.Utils.hasInStrings(strings, INTEGRITY_BYPASS_SIGS);

    if (hasAuthState) {
      findings.push({
        ruleId: 'mastg-auth-8-auth-state',
        ruleName: 'Local Authentication State Management',
        severity: 'issue',
        description: 'App manages authentication state locally via boolean flags ' +
          '(isAuthenticated, isLoggedIn). Client-side authentication state can be ' +
          'manipulated via Frida/Xposed hooks, memory dumps, or SharedPreferences ' +
          'edits. Verify that sensitive operations are authorized server-side ' +
          'regardless of local auth state.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Local auth state flags'
      });
    }

    if (hasBypass) {
      findings.push({
        ruleId: 'mastg-auth-8-bypass-flags',
        ruleName: 'Potential Authentication Bypass Mechanisms',
        severity: 'issue',
        description: 'App contains strings suggesting authentication bypass ' +
          '(bypassAuth, disableAuth, skipAuth, trustAll). These may be used for ' +
          'debug/development but if left enabled in production, they allow ' +
          'complete authentication bypass.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Bypass-related strings'
      });
    }

    if (hasDebugBypass) {
      findings.push({
        ruleId: 'mastg-auth-8-debug-bypass',
        ruleName: 'Debug Mode Security Controls',
        severity: 'info',
        description: 'App has debug-related security controls (isDebuggerConnected, ' +
          'debuggable checks). Verify these are used to deny access in debug ' +
          'mode, not to grant privileges.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Debug controls'
      });
    }

    if (hasRootBypass) {
      findings.push({
        ruleId: 'mastg-auth-8-root-detection',
        ruleName: 'Root Detection Present',
        severity: 'secure',
        description: 'App implements root detection. Verify that root detection ' +
          'is enforced in security-critical code paths and cannot be bypassed ' +
          'via Frida or Xposed hooks. The absence of a detection bypass does ' +
          'not make it effective.',
        cwe: '',
        owasp: '',
        masvs: 'RESILIENCE-1',
        file: 'classes.dex',
        line: null,
        match: 'Root detection'
      });
    }

    if (hasIntegrityBypass) {
      findings.push({
        ruleId: 'mastg-auth-8-integrity',
        ruleName: 'App Integrity Verification',
        severity: 'secure',
        description: 'App implements integrity verification (SafetyNet, PlayIntegrity). ' +
          'Verify that integrity failures result in denied access and are not ' +
          'bypassable through response manipulation.',
        cwe: '',
        owasp: '',
        masvs: 'RESILIENCE-4',
        file: 'classes.dex',
        line: null,
        match: 'Integrity verification'
      });
    }

    if (!hasAuthState && !hasBypass && !hasRootBypass && !hasIntegrityBypass) {
      findings.push({
        ruleId: 'mastg-auth-8-no-auth-controls',
        ruleName: 'No Local Auth Control Mechanisms',
        severity: 'info',
        description: 'No local authentication state management or bypass mechanisms ' +
          'detected. If the app requires authentication, server-side authorization ' +
          'should be enforced for all sensitive operations.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No auth controls'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
