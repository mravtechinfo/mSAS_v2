/**
 * mSAS v2 — Memory & iOS Resilience Scanner
 * RES-6: Memory Dumping Countermeasures (MASTG-RESILIENCE-5)
 * RES-7: iOS Obfuscation & Integrity (MASTG-RESILIENCE-6/7)
 * RES-8: iOS Attribution & Pasteboard (MASTG-STORAGE-3)
 */

var MSAS = MSAS || {};
MSAS.MemoryResilienceScanner = (function() {
  'use strict';

  var MEMORY_SIGS = [
    'Landroid/security/KeyChain', 'Ljava/security/KeyStore',
    'mprotect', 'mmap', 'Mmap', 'Landroid/system/MemMap',
    'Ldalvik/system/Unsafe', 'sun.misc.Unsafe',
    'Ldalvik/system/InMemoryDexClassLoader',
    'shouldEncrypt', 'encrypt', 'crypto',
    'Ljavax/crypto/Cipher', 'Ljavax/crypto/CipherOutputStream',
    'Ljavax/crypto/CipherInputStream'
  ];

  var IOS_RESILIENCE_SIGS = [
    'Lapple/security/SecRandom', 'Lsecurity/SecRandom',
    'Lapple/security/Keychain', 'Lsecurity/Security',
    'Lapple/foundation/NSData',
    'Lapple/foundation/NSKeyedArchiver',
    'Lapple/foundation/NSKeyedUnarchiver'
  ];

  var IOS_OBFUSCATION_SIGS = [
    'LC/CrashReporter', 'LPLCrashReporter',
    'LFBProcess', 'Lm.Delegate',
    'LLogical', 'Lcom/Logic/',
    'Lcom/Appsee', 'LAppsee',
    'LObfuscator', 'obfuscation',
    'LSecure', 'LProtection',
    'LSpotlight', 'LLocalization'
  ];

  var IOS_ATTRIBUTION_SIGS = [
    'AppTrackingTransparency', 'ATTrackingManager',
    'Lapple/AppTrackingTransparency',
    'Lcom/apple/AppTrackingTransparency',
    'UIPasteboard', 'Lapple/UIKit/UIPasteboard',
    'pasteboard', 'generalPasteboard',
    'Lcom/apple/uikit/UIPasteboard',
    'requestTrackingAuthorization', 'trackingAuthorizationStatus'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasMemory = MSAS.Utils.hasInStrings(strings, MEMORY_SIGS);
    var hasIOSResilience = MSAS.Utils.hasInStrings(strings, IOS_RESILIENCE_SIGS);
    var hasIOSObfuscation = MSAS.Utils.hasInStrings(strings, IOS_OBFUSCATION_SIGS);
    var hasAttribution = MSAS.Utils.hasInStrings(strings, IOS_ATTRIBUTION_SIGS);

    if (hasMemory) findings.push({
      ruleId: 'mastg-resilience-5-memory', ruleName: 'Memory Protection Mechanisms',
      severity: 'info',
      description: 'App uses memory protection APIs (mprotect, mmap, KeyStore, encryption). ' +
        'Verify sensitive data is cleared from memory after use and that ' +
        'hardware-backed keystore is used for cryptographic keys.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-5',
      file: 'classes.dex', line: null, match: 'Memory protection'
    });

    if (hasIOSResilience) findings.push({
      ruleId: 'mastg-resilience-6-ios-resilience', ruleName: 'iOS Resilience Mechanisms',
      severity: 'secure',
      description: 'App uses iOS security frameworks (Security, Keychain, NSData).',
      cwe: '', owasp: '', masvs: 'RESILIENCE-6',
      file: '', line: null, match: 'iOS resilience'
    });

    if (hasAttribution) findings.push({
      ruleId: 'mastg-resilience-4-ios-attribution', ruleName: 'iOS App Tracking Transparency',
      severity: 'secure',
      description: 'App implements AppTrackingTransparency for privacy compliance. ' +
        'Verify ATT prompt is displayed before tracking.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-4',
      file: '', line: null, match: 'ATT/Privacy'
    });

    if (!hasMemory && !hasIOSResilience && !hasAttribution) findings.push({
      ruleId: 'mastg-resilience-no-memory-protection', ruleName: 'No Memory Protection Detected',
      severity: 'info',
      description: 'No explicit memory protection or iOS resilience mechanisms detected.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-5',
      file: '', line: null, match: 'No memory protection'
    });

    return findings;
  }
  return { scan: scan };
})();
