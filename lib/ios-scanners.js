/**
 * mSAS v2 — iOS Platform Scanners (Combined)
 * NET-6: iOS ATS Analysis (MASTG-NETWORK-1)
 * PLAT-7: iOS URL Scheme Hijacking (MASTG-PLATFORM-3)
 * PLAT-8: iOS Keyboard Extension (MASTG-PLATFORM-6)
 * PLAT-9: iOS XPC / IPC Analysis (MASTG-PLATFORM-7)
 */

var MSAS = MSAS || {};
MSAS.IOSPlatformScanner = (function() {
  'use strict';

  var ATS_SIGS = [
    'NSAppTransportSecurity', 'NSAllowsArbitraryLoads',
    'NSAllowsArbitraryLoadsInWebContent', 'NSAllowsLocalNetworking',
    'NSExceptionDomains', 'NSIncludesSubdomains',
    'NSExceptionAllowsInsecureHTTPLoads', 'NSExceptionMinimumTLSVersion',
    'NSExceptionRequiresForwardSecrecy', 'NSTemporaryExceptionMinimumTLSVersion',
    'NSTemporaryExceptionAllowsInsecureHTTPLoads', 'ATS',
    'LSApplicationQueriesSchemes'
  ];

  var URL_SCHEME_SIGS = [
    'CFBundleURLSchemes', 'CFBundleURLTypes', 'CFBundleURLName',
    'LSApplicationQueriesSchemes', 'UIApplicationOpenURL',
    'canOpenURL', 'openURL', 'openURL:options:completionHandler',
    'Lobjc/Message', 'Lcom/apple/UIApplication',
    'Lapple/UIKit/UIApplication'
  ];

  var KEYBOARD_SIGS = [
    'UIInputViewController', 'UILexicon', 'UILexiconEntry',
    'Lcom/apple/UIKit/UIInputViewController',
    'UIKeyboardExtension', 'RequestSupplementaryLexicon',
    'documentContextBeforeInput', 'documentContextAfterInput',
    'hasFullAccess', 'Lcom/apple/UIKit/UITextInput',
    'NSExtensionPrincipalClass'
  ];

  var XPC_SIGS = [
    'NSXPCConnection', 'NSXPCInterface', 'NSXPCListener',
    'Lcom/apple/Foundation/NSXPCConnection',
    'xpc_connection', 'xpc_connection_create',
    'xpc_connection_send_message', 'xpc_connection_set_event_handler',
    'launchd', 'Lcom/apple/launchd',
    'mach_service', 'MachService',
    'Lcom/apple/Foundation/NSXPCListener',
    'xpc_dictionary', 'xpc_object'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasATS = MSAS.Utils.hasInStrings(strings, ATS_SIGS);
    var hasURLSchemes = MSAS.Utils.hasInStrings(strings, URL_SCHEME_SIGS);
    var hasKeyboard = MSAS.Utils.hasInStrings(strings, KEYBOARD_SIGS);
    var hasXPC = MSAS.Utils.hasInStrings(strings, XPC_SIGS);

    if (hasATS) {
      findings.push({
        ruleId: 'mastg-network-1-ios-ats', ruleName: 'iOS ATS (App Transport Security)',
        severity: 'info',
        description: 'iOS App Transport Security (ATS) configuration detected. ' +
          'Verify NSAllowsArbitraryLoads is not enabled and that NSExceptionDomains ' +
          'specify minimum TLS 1.2 and require forward secrecy.',
        cwe: 'CWE-319', owasp: 'M3', masvs: 'NETWORK-1',
        file: 'Info.plist', line: null, match: 'ATS config'
      });
    }
    if (hasURLSchemes) {
      findings.push({
        ruleId: 'mastg-platform-3-ios-url-schemes', ruleName: 'iOS URL Scheme / Universal Links',
        severity: 'info',
        description: 'App registers custom URL schemes or handles Universal Links. ' +
          'Verify URL scheme validation prevents interception by similarly-registered apps.',
        cwe: 'CWE-939', owasp: 'M1', masvs: 'PLATFORM-3',
        file: 'Info.plist', line: null, match: 'URL schemes'
      });
    }
    if (hasKeyboard) {
      findings.push({
        ruleId: 'mastg-platform-6-ios-keyboard', ruleName: 'iOS Keyboard Extension',
        severity: 'info',
        description: 'App includes a custom keyboard extension (UIInputViewController). ' +
          'Keyboard extensions capture all keystrokes and can exfiltrate sensitive data. ' +
          'Ensure secure text entry fields use UITextInputPasswordRules.',
        cwe: 'CWE-200', owasp: 'M2', masvs: 'PLATFORM-6',
        file: '', line: null, match: 'Keyboard extension'
      });
    }
    if (hasXPC) {
      findings.push({
        ruleId: 'mastg-platform-7-ios-xpc', ruleName: 'iOS XPC / IPC Services',
        severity: 'info',
        description: 'App uses XPC services or IPC mechanisms. Verify XPC connections ' +
          'validate the remote process identity using NSXPCListener and that ' +
          'messages are properly sanitized.',
        cwe: 'CWE-269', owasp: 'M1', masvs: 'PLATFORM-7',
        file: '', line: null, match: 'XPC/IPC'
      });
    }
    if (!hasATS && !hasURLSchemes && !hasKeyboard && !hasXPC) {
      findings.push({
        ruleId: 'mastg-ios-no-platform', ruleName: 'No iOS Platform Features Detected',
        severity: 'info',
        description: 'No iOS-specific platform features (ATS, URL schemes, keyboard, XPC) detected.',
        cwe: '', owasp: '', masvs: '',
        file: '', line: null, match: 'No iOS features'
      });
    }
    return findings;
  }
  return { scan: scan };
})();
