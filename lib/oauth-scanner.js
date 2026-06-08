/**
 * mSAS v2 — OAuth 2.0 / PKCE Verification Scanner
 * MASTG Ref: MASTG-AUTH-5 (OAuth 2.0 / PKCE)
 * CWE-862: Missing Authorization
 */

var MSAS = MSAS || {};
MSAS.OAuthScanner = (function() {
  'use strict';

  var CWE = 'CWE-862';
  var OWASP = 'M4';
  var MASVS = 'AUTH-5';

  var OAUTH_FLOW_SIGS = [
    'Lcom/google/android/gms/auth/api/signin/GoogleSignIn',
    'Lcom/google/android/gms/auth/api/signin/GoogleSignInOptions',
    'GoogleSignIn',
    'GoogleSignInOptions',
    'Lcom/facebook/login/LoginManager',
    'Lcom/facebook/FacebookSdk',
    'Lcom/google/android/gms/auth/api/credentials/Credential',
    'Lcom/google/android/gms/auth/api/credentials/CredentialsClient',
    'Lcom/google/android/gms/auth/api/identity',
    'Landroid/app/Activity;->startActivityForResult',
    'startActivityForResult'
  ];

  var OAUTH_TOKEN_SIGS = [
    'clientId',
    'client_id',
    'clientSecret',
    'client_secret',
    'clientID',
    'redirectUri',
    'redirect_uri',
    'redirectUrl',
    'REDIRECT_URI',
    'authorizationUrl',
    'authorization_endpoint',
    'tokenUrl',
    'token_endpoint',
    'grantType',
    'grant_type',
    'responseType',
    'response_type'
  ];

  var PKCE_SIGS = [
    'codeChallenge',
    'code_challenge',
    'codeVerifier',
    'code_verifier',
    'S256',
    'sha256',
    'SHA256',
    'codeChallengeMethod',
    'pkce',
    'PKCE'
  ];

  var OAUTH_LIB_SIGS = [
    'Lnet/openid/appauth',
    'Lnet/openid/appauth/AuthorizationService',
    'Lnet/openid/appauth/AuthorizationRequest',
    'Lnet/openid/appauth/TokenResponse',
    'AuthorizationService',
    'AppAuth',
    'Lcom/google/android/gms/auth/api/identity/BeginSignInRequest',
    'Lcom/google/android/gms/auth/api/identity/GetSignInIntentRequest',
    'Lcom/google/android/gms/auth/api/identity/AuthorizationClient'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasOAuthFlow = MSAS.Utils.hasInStrings(strings, OAUTH_FLOW_SIGS);
    var hasOAuthTokens = MSAS.Utils.hasInStrings(strings, OAUTH_TOKEN_SIGS);
    var hasPKCE = MSAS.Utils.hasInStrings(strings, PKCE_SIGS);
    var hasOAuthLib = MSAS.Utils.hasInStrings(strings, OAUTH_LIB_SIGS);

    if (hasOAuthFlow || hasOAuthTokens || hasOAuthLib) {
      findings.push({
        ruleId: 'mastg-auth-5-oauth-flow',
        ruleName: (hasOAuthLib ? 'AppAuth/OAuth 2.0 ' : 'OAuth 2.0 ') + 'Authorization Flow Detected',
        severity: hasPKCE ? 'secure' : 'issue',
        description: 'App implements OAuth 2.0 authorization' +
          (hasOAuthLib ? ' using AppAuth library' : '') + '.' +
          (hasPKCE
            ? ' ✅ PKCE (Proof Key for Code Exchange) is implemented, preventing ' +
              'authorization code interception attacks.'
            : ' ⚠️ No PKCE references detected. OAuth 2.0 without PKCE is vulnerable ' +
              'to authorization code interception by malicious apps with the same ' +
              'redirect URI scheme. Implement PKCE using code_challenge+S256.'),
        cwe: hasPKCE ? '' : CWE,
        owasp: hasPKCE ? '' : OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'OAuth 2.0 flow' + (hasPKCE ? ' + PKCE' : '')
      });
    }

    if (hasOAuthTokens && !hasOAuthFlow && !hasOAuthLib) {
      findings.push({
        ruleId: 'mastg-auth-5-oauth-config',
        ruleName: 'OAuth Configuration Fields Detected',
        severity: 'info',
        description: 'OAuth 2.0 configuration fields (client_id, redirect_uri, scope, etc.) ' +
          'found in DEX strings. This may indicate custom OAuth implementation ' +
          'rather than using a standard library like AppAuth. Custom OAuth ' +
          'implementations often have security flaws.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'OAuth config fields'
      });
    }

    if (!hasOAuthFlow && !hasOAuthTokens && !hasOAuthLib) {
      findings.push({
        ruleId: 'mastg-auth-5-no-oauth',
        ruleName: 'No OAuth 2.0 Authorization Detected',
        severity: 'info',
        description: 'No OAuth 2.0 authorization flow or configuration detected. ' +
          'If the app uses social login or third-party authentication, verify that ' +
          'PKCE and secure redirect URI handling are implemented.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No OAuth'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
