/**
 * mSAS v2 — Session Management Analysis Scanner
 * MASTG Ref: MASTG-AUTH-3 (Session Handling) / MASTG-AUTH-4 (Remote Auth)
 * CWE-613: Insufficient Session Expiration
 */

var MSAS = MSAS || {};
MSAS.SessionScanner = (function() {
  'use strict';

  var CWE = 'CWE-613';
  var OWASP = 'M4';
  var MASVS = 'AUTH-3';

  var SESSION_TOKEN_SIGS = [
    'sessionToken',
    'session_token',
    'sessionId',
    'session_id',
    'authToken',
    'auth_token',
    'accessToken',
    'access_token',
    'refreshToken',
    'refresh_token',
    'SESSION_ID',
    'SESSION_TOKEN',
    'ACCESS_TOKEN',
    'REFRESH_TOKEN'
  ];

  var AUTO_LOGIN_SIGS = [
    'autoLogin',
    'auto_login',
    'autoSignIn',
    'auto_sign_in',
    'rememberMe',
    'remember_me',
    'keepLoggedIn',
    'keep_logged_in',
    'staySignedIn',
    'stay_signed_in',
    'skipLogin',
    'isLoggedIn',
    'is_logged_in'
  ];

  var TIMEOUT_SIGS = [
    'sessionTimeout',
    'session_timeout',
    'expireAfter',
    'expirationTime',
    'tokenExpiry',
    'token_expiry',
    'timeout',
    'TIMEOUT',
    'invalidateSession',
    'invalidate',
    'clearSession',
    'logOut',
    'logout',
    'signOut',
    'signout',
    'onUserLogout'
  ];

  var JWT_SIGS = [
    'Lio/jsonwebtoken',
    'Jwts',
    'JWT',
    'jwt',
    'JsonWebToken',
    'Lcom/auth0/android/jwt',
    'Lcom/auth0/jwt',
    'Lio/jsonwebtoken/Claims'
  ];

  var TOKEN_STORAGE_SIGS = [
    'SharedPreferences',
    'getSharedPreferences',
    'getPreferences',
    'edit',
    'putString',
    'getString',
    'EncryptedSharedPreferences',
    'MasterKey',
    'Landroidx/security/crypto/MasterKey',
    'Landroidx/security/crypto/EncryptedSharedPreferences'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasSessionTokens = MSAS.Utils.hasInStrings(strings, SESSION_TOKEN_SIGS);
    var hasAutoLogin = MSAS.Utils.hasInStrings(strings, AUTO_LOGIN_SIGS);
    var hasTimeout = MSAS.Utils.hasInStrings(strings, TIMEOUT_SIGS);
    var hasJWT = MSAS.Utils.hasInStrings(strings, JWT_SIGS);
    var hasTokenStorage = MSAS.Utils.hasInStrings(strings, TOKEN_STORAGE_SIGS);

    // Check if encrypted storage is used
    var hasEncryptedStorage = strings.some(function(s) {
      return s.indexOf('EncryptedSharedPreferences') >= 0 ||
             s.indexOf('MasterKey') >= 0 ||
             s.indexOf('androidx.security.crypto') >= 0;
    });

    if (hasSessionTokens || hasJWT) {
      findings.push({
        ruleId: 'mastg-auth-3-session-tokens',
        ruleName: hasJWT ? 'JWT Token Usage Detected' : 'Session/Auth Token Fields Detected',
        severity: hasEncryptedStorage ? 'secure' : 'issue',
        description: 'App uses ' + (hasJWT ? 'JWT tokens ' : 'session/auth tokens ') +
          (hasAutoLogin ? 'with auto-login/remember-me ' : '') +
          (hasTimeout ? 'and session timeout/logout logic. ' : 'without explicit session timeout detected. ') +
          (hasEncryptedStorage
            ? 'Tokens stored using EncryptedSharedPreferences - good practice.'
            : '⚠️ Token storage uses standard SharedPreferences. Auth tokens ' +
              'should be stored in EncryptedSharedPreferences or Android KeyStore ' +
              'to prevent extraction from backup or file reads.'),
        cwe: hasEncryptedStorage ? '' : CWE,
        owasp: hasEncryptedStorage ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasJWT ? 'JWT ' : 'Session tokens ') +
          (hasAutoLogin ? '+ auto-login ' : '') +
          (hasTimeout ? '+ timeout ' : '') +
          (hasEncryptedStorage ? '(encrypted storage)' : '(plain storage)')
      });
    }

    if (hasAutoLogin && !hasSessionTokens && !hasJWT) {
      findings.push({
        ruleId: 'mastg-auth-3-auto-login',
        ruleName: 'Auto-Login / Remember Me',
        severity: 'info',
        description: 'App implements auto-login or remember-me functionality. ' +
          'Verify that session persistence uses secure token storage (EncryptedSharedPreferences) ' +
          'and that session timeout is enforced after inactivity.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'Auto-login'
      });
    }

    if (!hasSessionTokens && !hasAutoLogin && !hasJWT && !hasTimeout) {
      findings.push({
        ruleId: 'mastg-auth-3-no-session',
        ruleName: 'No Session Management APIs Detected',
        severity: 'info',
        description: 'No session management, token, or auto-login references found. ' +
          'If the app uses remote authentication, verify that session tokens are ' +
          'securely stored and managed.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No session management'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
