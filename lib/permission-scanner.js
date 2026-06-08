/**
 * mSAS v2 — Permission Audit Scanner
 * MASTG Ref: MASTG-CODE-6 (Permission Over-Provisioning)
 * CWE-272: Least Privilege Violation
 */

var MSAS = MSAS || {};
MSAS.PermissionScanner = (function() {
  'use strict';

  var CWE = 'CWE-272';
  var OWASP = 'M8';
  var MASVS = 'CODE-6';

  var DANGEROUS_PERMS = [
    'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION',
    'ACCESS_BACKGROUND_LOCATION', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS',
    'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE',
    'READ_SMS', 'RECEIVE_SMS', 'SEND_SMS', 'READ_PHONE_STATE', 'CALL_PHONE',
    'READ_CALENDAR', 'WRITE_CALENDAR', 'READ_CALL_LOG', 'WRITE_CALL_LOG',
    'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN',
    'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO',
    'POST_NOTIFICATIONS', 'NEARBY_WIFI_DEVICES', 'MANAGE_EXTERNAL_STORAGE'
  ];

  var DANGEROUS_COMBOS = [
    { combo: 'CAMERA + RECORD_AUDIO', sigs: ['CAMERA', 'RECORD_AUDIO'] },
    { combo: 'LOCATION + INTERNET', sigs: ['ACCESS_FINE_LOCATION', 'ACCESS_COARSE_LOCATION'] },
    { combo: 'SMS FULL ACCESS', sigs: ['READ_SMS', 'SEND_SMS', 'RECEIVE_SMS'] },
    { combo: 'CONTACTS + PHONE', sigs: ['READ_CONTACTS', 'READ_PHONE_STATE', 'CALL_PHONE'] },
    { combo: 'STORAGE + CAMERA', sigs: ['READ_EXTERNAL_STORAGE', 'CAMERA'] },
    { combo: 'BLUETOOTH + LOCATION', sigs: ['BLUETOOTH_SCAN', 'ACCESS_FINE_LOCATION'] }
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    // Detect dangerous permissions declared in DEX strings
    var dangerousFound = [];
    for (var i = 0; i < DANGEROUS_PERMS.length; i++) {
      var perm = DANGEROUS_PERMS[i];
      if (strings.some(function(s) { return s.indexOf(perm) >= 0; })) {
        dangerousFound.push(perm);
      }
    }

    // Detect dangerous combinations
    var riskyCombos = [];
    for (var j = 0; j < DANGEROUS_COMBOS.length; j++) {
      var combo = DANGEROUS_COMBOS[j];
      var foundAll = true;
      for (var k = 0; k < combo.sigs.length; k++) {
        if (!strings.some(function(s) { return s.indexOf(combo.sigs[k]) >= 0; })) {
          foundAll = false;
          break;
        }
      }
      if (foundAll) {
        riskyCombos.push(combo.combo);
      }
    }

    if (dangerousFound.length > 0) {
      findings.push({
        ruleId: 'mastg-code-6-dangerous-permissions',
        ruleName: 'Dangerous Permission' + (dangerousFound.length > 1 ? 's' : '') + ' Declared',
        severity: 'info',
        description: 'App declares ' + dangerousFound.length + ' dangerous permission' +
          (dangerousFound.length > 1 ? 's' : '') + ': ' + dangerousFound.slice(0, 10).join(', ') +
          (dangerousFound.length > 10 ? '...' : '') + '. ' +
          'Verify each permission is actually used and follow the principle of least privilege.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'AndroidManifest.xml',
        line: null,
        match: dangerousFound.slice(0, 8).join(', ')
      });
    }

    if (riskyCombos.length > 0) {
      findings.push({
        ruleId: 'mastg-code-6-risky-combos',
        ruleName: 'Risky Permission Combinations',
        severity: 'issue',
        description: 'App declares dangerous permission combinations: ' +
          riskyCombos.join(', ') + '. These combinations can be abused by malware ' +
          'if the app has vulnerabilities. Review whether all permissions are ' +
          'strictly necessary and implement runtime permission checks.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'AndroidManifest.xml',
        line: null,
        match: riskyCombos.join(', ')
      });
    }

    if (dangerousFound.length === 0) {
      findings.push({
        ruleId: 'mastg-code-6-no-dangerous-perms',
        ruleName: 'No Dangerous Permissions Declared',
        severity: 'secure',
        description: 'No dangerous Android permissions detected in the app.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No dangerous permissions'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
