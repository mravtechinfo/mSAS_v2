/**
 * mSAS v2 — Device Access Controls Scanner
 * MASTG Ref: MASTG-STORAGE-10 (Device Access Security)
 * CWE-287: Improper Authentication
 */

var MSAS = MSAS || {};
MSAS.DeviceAccessScanner = (function() {
  'use strict';

  var CWE = 'CWE-287';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-10';

  var SCREEN_LOCK_SIGS = [
    'Landroid/app/KeyguardManager',
    'isDeviceSecure',
    'isKeyguardSecure',
    'createConfirmDeviceCredentialIntent',
    'Landroid/biometrics/BiometricPrompt',
    'Landroidx/biometrics/BiometricPrompt',
    'setDeviceCredentialAllowed',
    'LOCK_PATTERN_ENABLED',
    'LOCK_PIN_ENABLED',
    'KEYGUARD_PRESENT'
  ];

  var ROOT_DETECTION_SIGS = [
    'RootBeer',
    'Lcom/scottyab/rootbeer/RootBeer',
    'isRooted',
    'suBinary',
    'checkForRoot',
    'busybox',
    'test-keys',
    'buildTags',
    'checkSuBinary',
    'isRootedWithBusyBoxCheck',
    'detectRootManagementApps',
    'detectPotentiallyDangerousApps',
    'detectTestKeys',
    'detectSuBinary'
  ];

  var JAILBREAK_DETECTION_SIGS = [
    'isJailbroken',
    'checkJailbreak',
    'Lcom/scottyab/rootbeer/RootBeer',
    'Cydia',
    'Sileo',
    'substrate',
    'MobileSubstrate',
    'jailbreak',
    'sandboxIntegrity'
  ];

  var DEVICE_ADMIN_SIGS = [
    'Landroid/app/admin/DevicePolicyManager',
    'DeviceAdminReceiver',
    'Landroid/app/admin/DeviceAdminReceiver',
    'getDevicePolicyManager',
    'isAdminActive',
    'lockNow',
    'wipeData',
    'resetPassword',
    'getPasswordQuality',
    'getPasswordMinimumLength'
  ];

  var EMULATOR_DETECTION_SIGS = [
    'isEmulator',
    'emulatorDetected',
    'checkEmulator',
    'Build.FINGERPRINT',
    'BUILD_FINGERPRINT',
    'ro.kernel.qemu',
    'Landroid/os/Build;->FINGERPRINT',
    'Landroid/os/Build;->MODEL',
    'Landroid/os/Build;->MANUFACTURER',
    'Landroid/os/Build;->BRAND'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasScreenLock = MSAS.Utils.hasInStrings(strings, SCREEN_LOCK_SIGS);
    var hasRootDetect = MSAS.Utils.hasInStrings(strings, ROOT_DETECTION_SIGS);
    var hasJailbreakDetect = MSAS.Utils.hasInStrings(strings, JAILBREAK_DETECTION_SIGS);
    var hasDeviceAdmin = MSAS.Utils.hasInStrings(strings, DEVICE_ADMIN_SIGS);
    var hasEmulatorDetect = MSAS.Utils.hasInStrings(strings, EMULATOR_DETECTION_SIGS);

    var detectCount = 0;
    if (hasRootDetect) detectCount++;
    if (hasJailbreakDetect) detectCount++;
    if (hasEmulatorDetect) detectCount++;

    // Screen lock detection
    if (hasScreenLock) {
      findings.push({
        ruleId: 'mastg-storage-10-screen-lock',
        ruleName: 'Device Lock Screen Verification Detected',
        severity: 'secure',
        description: 'App checks for device lock screen (PIN, pattern, password, biometric). ' +
          'This is good practice for protecting sensitive app data. Verify that the check ' +
          'is enforced on app startup and not bypassable.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'KeyguardManager/BiometricPrompt API'
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-10-no-screen-lock',
        ruleName: 'No Device Lock Screen Verification',
        severity: 'info',
        description: 'No device lock screen verification (KeyguardManager, BiometricPrompt) ' +
          'detected. Consider verifying device lock status before displaying sensitive data.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No lock screen check'
      });
    }

    // Root/jailbreak/emulator detection
    if (detectCount > 0) {
      var protections = [];
      if (hasRootDetect) protections.push('root detection');
      if (hasJailbreakDetect) protections.push('jailbreak detection');
      if (hasEmulatorDetect) protections.push('emulator detection');

      findings.push({
        ruleId: 'mastg-storage-10-tamper-detection',
        ruleName: 'Tamper Detection Mechanism Found',
        severity: 'secure',
        description: 'App implements ' + protections.join(', ') + '. ' +
          'Verify these checks are enforced in security-critical code paths and ' +
          'cannot be easily bypassed via Frida/Xposed hooks.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: protections.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-10-no-tamper-detection',
        ruleName: 'No Tamper Detection Mechanisms',
        severity: 'info',
        description: 'No root/jailbreak/emulator detection references found. ' +
          'For apps handling sensitive data, implementing device integrity checks ' +
          'raises the bar against reverse engineering and tampering.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No tamper detection'
      });
    }

    // Device admin
    if (hasDeviceAdmin) {
      findings.push({
        ruleId: 'mastg-storage-10-device-admin',
        ruleName: 'Device Admin API Usage Detected',
        severity: 'info',
        description: 'App uses DevicePolicyManager API. If the app is an MDM/EMM or ' +
          'enterprise app this is expected. Verify password policy enforcement ' +
          '(setPasswordQuality, setPasswordMinimumLength) and that device admin ' +
          'is requested with clear user consent.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'DevicePolicyManager API'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
