/**
 * mSAS v2 — Content Provider Security Scanner
 * MASTG Ref: MASTG-PLATFORM-4 (Content Provider Security)
 * CWE-89: SQL Injection
 */

var MSAS = MSAS || {};
MSAS.ContentProviderScanner = (function() {
  'use strict';

  var CWE = 'CWE-89';
  var OWASP = 'M7';
  var MASVS = 'PLATFORM-4';

  var PROVIDER_SIGS = [
    'Landroid/content/ContentProvider',
    'Landroid/content/ContentResolver',
    'ContentProvider',
    'ContentResolver',
    'Landroid/database/sqlite/SQLiteOpenHelper',
    'SQLiteOpenHelper'
  ];

  var URI_PERMISSION_SIGS = [
    'grantUriPermission',
    'takePersistableUriPermission',
    'FLAG_GRANT_READ_URI_PERMISSION',
    'FLAG_GRANT_WRITE_URI_PERMISSION',
    'grantUriPermissions',
    'android:grantUriPermissions'
  ];

  var SQL_INJECTION_SIGS = [
    'rawQuery',
    'execSQL',
    'rawQueryWithFactory',
    'compileStatement',
    'Landroid/database/sqlite/SQLiteDatabase;->rawQuery',
    'Landroid/database/sqlite/SQLiteDatabase;->execSQL'
  ];

  var PATH_TRAVERSAL_SIGS = [
    'openFile',
    'Landroid/content/ContentProvider;->openFile',
    'getFileStreamPath',
    'getPath',
    'getCanonicalPath',
    'getAbsolutePath',
    'canonicalPath',
    '..\\/',
    '../'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasProvider = MSAS.Utils.hasInStrings(strings, PROVIDER_SIGS);
    var hasUriPermission = MSAS.Utils.hasInStrings(strings, URI_PERMISSION_SIGS);
    var hasSQLInjection = MSAS.Utils.hasInStrings(strings, SQL_INJECTION_SIGS);
    var hasPathTraversal = MSAS.Utils.hasInStrings(strings, PATH_TRAVERSAL_SIGS);

    if (hasProvider) {
      findings.push({
        ruleId: 'mastg-platform-4-provider-security',
        ruleName: 'Content Provider Implementation',
        severity: hasSQLInjection ? 'issue' : (hasUriPermission ? 'info' : 'secure'),
        description: 'App implements Content Provider or uses ContentResolver. ' +
          (hasSQLInjection
            ? ' ⚠️ Raw SQL queries detected (rawQuery/execSQL). If these use ' +
              'user-supplied input from content URIs, they are vulnerable to ' +
              'SQL injection. Use parameterized queries with selectionArgs.'
            : '') +
          (hasUriPermission
            ? ' URI permission grants are configured. Verify that grantUriPermissions ' +
              'is only used for specific provider paths.'
            : '') +
          (hasPathTraversal
            ? ' ⚠️ Path traversal risk: openFile/getPath usage detected. Verify ' +
              'path canonicalization to prevent directory traversal attacks.'
            : ''),
        cwe: hasSQLInjection ? CWE : '',
        owasp: hasSQLInjection ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasSQLInjection ? 'SQL injection risk' : '') +
          (hasPathTraversal ? (hasSQLInjection ? ' + ' : '') + 'path traversal' : '') +
          (!hasSQLInjection && !hasPathTraversal ? 'Content provider' : '')
      });
    }

    if (!hasProvider) {
      findings.push({
        ruleId: 'mastg-platform-4-no-provider',
        ruleName: 'No Content Provider Usage Detected',
        severity: 'secure',
        description: 'No Content Provider or ContentResolver usage detected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No content provider'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
