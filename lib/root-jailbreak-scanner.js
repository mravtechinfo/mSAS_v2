/**
 * mSAS v2 — Root & Jailbreak Detection Scanner
 * RES-1: Root Detection Bypass (MASTG-RESILIENCE-1)
 * RES-2: Jailbreak Detection Bypass (MASTG-RESILIENCE-1)
 */

var MSAS = MSAS || {};
MSAS.RootJailbreakScanner = (function() {
  'use strict';

  var ROOT_SIGS = [
    'isRooted', 'isDeviceRooted', 'checkForRoot', 'checkRoot',
    'RootBeer', 'Lcom/scottyab/rootbeer/RootBeer',
    'suBinary', 'checkSuBinary', 'detectSuBinary',
    'detectRootManagementApps', 'detectPotentiallyDangerousApps',
    'detectTestKeys', 'busybox', 'buildTags',
    'test-keys', '/system/xbin/su', '/system/app/Superuser',
    'com.noshufou.android.su', 'com.thirdparty.superuser',
    'eu.chainfire.supersu', 'com.topjohnwu.magisk'
  ];

  var JAILBREAK_SIGS = [
    'isJailbroken', 'checkJailbreak', 'detectJailbreak',
    'Cydia', 'Sileo', 'Zebra', 'Installer5',
    'MobileSubstrate', 'Substrate', 'substrate',
    'cydia://', 'cydia.list',
    '/Applications/Cydia.app', '/Library/MobileSubstrate',
    '/usr/libexec/sftp-server', '/bin/bash', '/etc/apt',
    'fstab', 'sandboxIntegrity', 'forkTest',
    'symlinkTest', 'plistModification'
  ];

  var EMULATOR_SIGS = [
    'isEmulator', 'detectEmulator', 'checkEmulator',
    'ro.kernel.qemu',
    'Landroid/os/Build;->FINGERPRINT', 'Landroid/os/Build;->MODEL',
    'Landroid/os/Build;->MANUFACTURER', 'Landroid/os/Build;->BRAND',
    'sdk_google', 'google_sdk',
    'goldfish', 'ranchu'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasRoot = MSAS.Utils.hasInStrings(strings, ROOT_SIGS);
    var hasJailbreak = MSAS.Utils.hasInStrings(strings, JAILBREAK_SIGS);
    var hasEmulator = MSAS.Utils.hasInStrings(strings, EMULATOR_SIGS);

    if (hasRoot) findings.push({
      ruleId: 'mastg-resilience-1-root-detect', ruleName: 'Root Detection Implemented',
      severity: 'secure',
      description: 'App detects rooted Android devices. Root detection raises the ' +
        'bar for attackers but can be bypassed with Magisk Hide, Frida, or KernelSU.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-1',
      file: 'classes.dex', line: null, match: 'Root detection'
    });

    if (hasJailbreak) findings.push({
      ruleId: 'mastg-resilience-1-jailbreak-detect', ruleName: 'Jailbreak Detection Implemented',
      severity: 'secure',
      description: 'App detects jailbroken iOS devices. Jailbreak detection can be ' +
        'bypassed by tools like Shadow, Choicy, or Frida.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-1',
      file: '', line: null, match: 'Jailbreak detection'
    });

    if (hasEmulator) findings.push({
      ruleId: 'mastg-resilience-3-emulator-detect', ruleName: 'Emulator Detection Implemented',
      severity: 'secure',
      description: 'App detects emulator environments to prevent analysis sandboxes.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-3',
      file: 'classes.dex', line: null, match: 'Emulator detection'
    });

    if (!hasRoot && !hasJailbreak && !hasEmulator) findings.push({
      ruleId: 'mastg-resilience-1-no-detect', ruleName: 'No Device Integrity Checks',
      severity: 'info',
      description: 'No root, jailbreak, or emulator detection detected.',
      cwe: '', owasp: '', masvs: 'RESILIENCE-1',
      file: '', line: null, match: 'No integrity checks'
    });

    return findings;
  }
  return { scan: scan };
})();
