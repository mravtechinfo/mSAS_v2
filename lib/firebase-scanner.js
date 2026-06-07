/**
 * mSAS v2 — Firebase Database & SDK Detection Scanner
 * 
 * Scans APK for Firebase service usage patterns:
 * - Firebase SDK package names (com.google.firebase.*)
 * - Firebase Realtime Database URLs
 * - Cloud Firestore references
 * - Firebase Authentication
 * - Firebase Cloud Storage / Cloud Messaging / Crashlytics
 * - google-services.json embedded in APK
 * 
 * MASTG Ref: MASTG-STORAGE-1 / MASTG-NETWORK-1
 * CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
 * 
 * Outputs v1-compatible findings: { ruleId, ruleName, severity, description, cwe, owasp, masvs, file, line, match }
 */

var MSAS = MSAS || {};
MSAS.FirebaseScanner = (function() {
  'use strict';

  var CWE = 'CWE-200';
  var OWASP = 'M1';
  var MASVS = 'STORAGE-12';

  /** Firebase SDK package signatures */
  var FIREBASE_SDKS = [
    { sig: 'Lcom/google/firebase/FirebaseApp',         name: 'Firebase Core',               severity: 'info' },
    { sig: 'Lcom/google/firebase/database',            name: 'Firebase Realtime Database',  severity: 'issue' },
    { sig: 'Lcom/google/firebase/firestore',           name: 'Cloud Firestore',             severity: 'issue' },
    { sig: 'Lcom/google/firebase/auth',                name: 'Firebase Authentication',     severity: 'info' },
    { sig: 'Lcom/google/firebase/storage',             name: 'Cloud Storage',               severity: 'info' },
    { sig: 'Lcom/google/firebase/messaging',           name: 'Cloud Messaging (FCM)',       severity: 'info' },
    { sig: 'Lcom/google/firebase/crashlytics',         name: 'Crashlytics',                 severity: 'info' },
    { sig: 'Lcom/google/firebase/analytics',           name: 'Google Analytics for Firebase', severity: 'info' },
    { sig: 'Lcom/google/firebase/config',              name: 'Remote Config',               severity: 'info' },
    { sig: 'Lcom/google/firebase/perf',                name: 'Performance Monitoring',      severity: 'info' },
    { sig: 'Lcom/google/firebase/inappmessaging',      name: 'In-App Messaging',            severity: 'info' },
    { sig: 'Lcom/google/firebase/dynamiclinks',        name: 'Dynamic Links',               severity: 'info' },
    { sig: 'Lcom/google/firebase/ml',                  name: 'ML Kit',                      severity: 'info' }
  ];

  /** Firebase Realtime DB / Firestore URL patterns to scan in DEX strings */
  var DB_URL_SIGS = [
    '.firebaseio.com',
    '.firebasedatabase.app',
    '.firestore.googleapis.com'
  ];

  /** google-services.json related patterns */
  var GOOGLE_SERVICES_SIGS = [
    'google-services.json',
    'google_services',
    'google-services'
  ];

  /**
   * Main scan function — produces v1-compatible findings
   */
  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var files = opts.files || [];
    var findings = [];

    // 1. Detect which Firebase SDK services are used
    var foundSdks = detectSdks(strings);
    var hasFirebase = foundSdks.length > 0;

    // 2. Detect Firebase Realtime Database and Firestore URLs
    var dbUrls = findUrls(strings, DB_URL_SIGS);

    // 3. Check for google-services.json in APK files
    var hasServicesJson = files.some(function(f) {
      return f.indexOf('google-services.json') >= 0 || f.indexOf('google_services') >= 0;
    });

    if (hasFirebase) {
      // Categorize by storage severity
      var hasDb     = foundSdks.some(function(s) { return s === 'Firebase Realtime Database' || s === 'Cloud Firestore'; });
      var hasAuth   = foundSdks.some(function(s) { return s === 'Firebase Authentication'; });
      var hasCore   = foundSdks.some(function(s) { return s === 'Firebase Core'; });

      // Report Firebase SDK summary
      var dbUrlStr = dbUrls.length > 0 ? dbUrls.slice(0, 3).join(', ') : 'none found';
      findings.push({
        ruleId: 'mastg-storage-12-firebase-sdk',
        ruleName: foundSdks.length + ' Firebase Service(s) Detected',
        severity: hasDb ? 'issue' : 'info',
        description: 'App uses Firebase SDK services: ' + foundSdks.join(', ') + '.' +
          (dbUrls.length > 0
            ? ' Database URL(s) found: ' + dbUrlStr + '. '
            : ' No database URLs found in DEX strings. ') +
          'Firebase databases (Realtime DB / Firestore) must have proper security rules configured. ' +
          'Open Firebase databases can expose all data to unauthenticated users. ' +
          (hasAuth
            ? ' Firebase Authentication is present — ensure proper token validation in security rules.'
            : ''),
        cwe: hasDb ? CWE : '',
        owasp: OWASP_M2,
        masvs: MASVS,
        file: hasServicesJson ? 'assets/google-services.json' : 'classes.dex',
        line: null,
        match: 'Services: ' + foundSdks.join(', ') + ' | DB URLs: ' + dbUrlStr
      });

      // Firestore-specific finding
      if (foundSdks.indexOf('Cloud Firestore') >= 0) {
        findings.push({
          ruleId: 'mastg-storage-12-firestore',
          ruleName: 'Cloud Firestore SDK Detected',
          severity: 'issue',
          description: 'Cloud Firestore is used for real-time NoSQL data storage. Firestore security rules ' +
            'must restrict read/write access using request.auth validation. Unsecured Firestore databases ' +
            'can be read/written by anyone who discovers the project ID. Verify rules in Firebase Console.',
          cwe: CWE,
          owasp: OWASP_M2,
          masvs: MASVS,
          file: 'classes.dex',
          line: null,
          match: 'Cloud Firestore detected'
        });
      }

      // Realtime Database-specific finding
      if (foundSdks.indexOf('Firebase Realtime Database') >= 0) {
        findings.push({
          ruleId: 'mastg-storage-12-realtime-db',
          ruleName: 'Firebase Realtime Database SDK Detected',
          severity: 'issue',
          description: 'Firebase Realtime Database SDK is used. ' +
            (dbUrls.length > 0
              ? 'Database URL(s): ' + dbUrlStr + '. '
              : 'Database URL may be constructed at runtime. ') +
            'Verify Realtime Database security rules require auth and validate data structure. ' +
            'Rules set to "true" allow anyone to read/write the entire database.',
          cwe: CWE,
          owasp: OWASP_M2,
          masvs: MASVS,
          file: 'classes.dex',
          line: null,
          match: dbUrls.length > 0 ? 'URLs: ' + dbUrlStr : 'Realtime DB SDK detected'
        });
      }

      // google-services.json presence
      if (hasServicesJson) {
        findings.push({
          ruleId: 'mastg-storage-12-google-services',
          ruleName: 'google-services.json Detected in APK',
          severity: 'info',
          description: 'google-services.json file is embedded in the APK assets or resources. ' +
            'This file contains Firebase project configuration including the API key, project ID, ' +
            'and database URL. The API key is not a secret for Firebase services, but the file ' +
            'reveals your Firebase project structure. Restrict API key usage in GCP console.',
          cwe: '',
          owasp: OWASP_M2,
          masvs: MASVS,
          file: 'google-services.json',
          line: null,
          match: 'Firebase config file in APK'
        });
      }

    } else if (dbUrls.length > 0) {
      // Firebase URLs found but no SDK references — maybe string constants
      var urlList = dbUrls.slice(0, 3).join(', ');
      findings.push({
        ruleId: 'mastg-storage-12-firebase-urls-only',
        ruleName: 'Firebase Database URLs Found (No Firebase SDK Detected)',
        severity: 'issue',
        description: 'Firebase Realtime Database URLs found in DEX strings: ' + urlList + '. ' +
          'No Firebase SDK references were detected. The URLs may be constructed dynamically or ' +
          'referenced through a REST API client. Verify that the Firebase Realtime Database has ' +
          'proper security rules configured in the Firebase Console.',
        cwe: CWE,
        owasp: OWASP_M2,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'URLs: ' + urlList
      });
    } else {
      // No Firebase at all
      findings.push({
        ruleId: 'mastg-storage-12-no-firebase',
        ruleName: 'No Firebase SDK or Database References Found',
        severity: 'secure',
        description: 'No Firebase SDK packages, Realtime Database URLs, or Firestore references ' +
          'were detected. The app does not use Firebase for backend services.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No Firebase references'
      });
    }

    return findings;
  }

  /**
   * Detect which Firebase SDK services are used in DEX strings
   */
  function detectSdks(strings) {
    var found = [];
    var limit = Math.min(strings.length, 50000);

    for (var s = 0; s < FIREBASE_SDKS.length; s++) {
      var sdk = FIREBASE_SDKS[s];
      for (var i = 0; i < limit; i++) {
        if (strings[i].indexOf(sdk.sig) >= 0) {
          found.push(sdk.name);
          break;
        }
      }
    }
    return found;
  }

  /**
   * Find Firebase database URLs in DEX strings
   */
  function findUrls(strings, urlSigs) {
    var limit = Math.min(strings.length, 50000);
    var found = [];

    for (var u = 0; u < urlSigs.length; u++) {
      var sig = urlSigs[u];
      for (var i = 0; i < limit; i++) {
        if (strings[i].indexOf(sig) >= 0) {
          // Extract the full URL/domain
          var s = strings[i];
          // Try to extract a meaningful prefix
          var idx = s.indexOf(sig);
          var start = Math.max(0, idx - 40);
          var match = (start > 0 ? '...' : '') + s.substring(start, idx + sig.length);
          if (match.length > 60) match = '...' + match.substring(match.length - 60);
          if (found.indexOf(match) < 0) found.push(match);
          break;
        }
      }
    }
    return found;
  }

  return { scan: scan };
})();
