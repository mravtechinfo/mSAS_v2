/**
 * mSAS v2 — Cache & Temp File Analysis Scanner
 * MASTG Ref: MASTG-STORAGE-6 (Cache Data Leakage)
 * CWE-524: Information Exposure Through Caching
 */

var MSAS = MSAS || {};
MSAS.CacheScanner = (function() {
  'use strict';

  var CWE = 'CWE-524';
  var OWASP = 'M2';
  var MASVS = 'STORAGE-6';

  var CACHE_DIR_SIGS = [
    'getCacheDir',
    'Landroid/content/Context;->getCacheDir',
    'getExternalCacheDir',
    'Landroid/content/Context;->getExternalCacheDir',
    'getTempDir',
    'getTempFile',
    'Ljava/io/File;->createTempFile',
    'createTempFile'
  ];

  var WEBVIEW_CACHE_SIGS = [
    'Landroid/webkit/WebView',
    'getSettings',
    'setAppCacheEnabled',
    'setAppCachePath',
    'setDatabaseEnabled',
    'setDatabasePath',
    'setDomStorageEnabled',
    'setCacheMode',
    'WebChromeClient',
    'onExceededDatabaseQuota',
    'Landroid/webkit/WebStorage'
  ];

  var OKHTTP_CACHE_SIGS = [
    'Lokhttp3/Cache',
    'Lokhttp3/OkHttpClient$Builder;->cache',
    'Lcom/squareup/okhttp/Cache',
    'OkHttpClient'
  ];

  var URLCACHE_SIGS = [
    'Landroid/net/http/HttpResponseCache',
    'Ljava/net/ResponseCache',
    'setDefault',
    'Ljava/net/HttpURLConnection'
  ];

  var SD_CARD_CACHE_SIGS = [
    'getExternalFilesDir',
    'getExternalStorageDirectory',
    'Landroid/os/Environment;->getExternalStorageDirectory',
    'Landroid/os/Environment;->getExternalStoragePublicDirectory',
    'WRITE_EXTERNAL_STORAGE',
    'READ_EXTERNAL_STORAGE'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasCacheDir = MSAS.Utils.hasInStrings(strings, CACHE_DIR_SIGS);
    var hasWebViewCache = MSAS.Utils.hasInStrings(strings, WEBVIEW_CACHE_SIGS);
    var hasOkHttpCache = MSAS.Utils.hasInStrings(strings, OKHTTP_CACHE_SIGS);
    var hasUrlCache = MSAS.Utils.hasInStrings(strings, URLCACHE_SIGS);
    var hasSdCardCache = MSAS.Utils.hasInStrings(strings, SD_CARD_CACHE_SIGS);

    var cacheMechanisms = [];
    if (hasCacheDir) cacheMechanisms.push('internal cache dir');
    if (hasWebViewCache) cacheMechanisms.push('WebView cache');
    if (hasOkHttpCache) cacheMechanisms.push('OkHttp cache');
    if (hasUrlCache) cacheMechanisms.push('HTTP response cache');
    if (hasSdCardCache) cacheMechanisms.push('external/SD storage');

    if (cacheMechanisms.length > 0) {
      findings.push({
        ruleId: 'mastg-storage-6-cache-detected',
        ruleName: 'Caching Mechanisms Detected',
        severity: cacheMechanisms.length > 2 ? 'issue' : 'info',
        description: 'App uses ' + cacheMechanisms.length + ' caching mechanism' +
          (cacheMechanisms.length > 1 ? 's' : '') + ': ' + cacheMechanisms.join(', ') + '. ' +
          'Cache files may contain sensitive data such as API responses, authentication ' +
          'tokens, or user information. Verify that caches are cleared on logout and that ' +
          'sensitive data is not cached. ' +
          (hasSdCardCache
            ? 'Using external storage for caching stores data outside the app sandbox ' +
              'where other apps may read it. Prefer getCacheDir() for sensitive data.'
            : ''),
        cwe: hasSdCardCache ? CWE : '',
        owasp: hasSdCardCache ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: cacheMechanisms.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-storage-6-no-cache',
        ruleName: 'No Caching Mechanisms Detected',
        severity: 'secure',
        description: 'No explicit caching mechanisms detected. If the app uses ' +
          'network libraries with built-in caching (OkHttp, Retrofit, etc.), ' +
          'verify cache policies are appropriately configured.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No caching APIs'
      });
    }

    // WebView cache specific warning
    if (hasWebViewCache) {
      findings.push({
        ruleId: 'mastg-storage-6-webview-cache',
        ruleName: 'WebView Cache — Sensitive Data Risk',
        severity: 'info',
        description: 'WebView caching is enabled (database, DOM storage, or app cache). ' +
          'WebView caches can store form data, authentication tokens, and page content. ' +
          'Ensure WebView caches are cleared when the user logs out and that sensitive ' +
          'pages use Cache-Control: no-store headers.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'WebView cache'
      });
    }

    // External storage warning
    if (hasSdCardCache) {
      findings.push({
        ruleId: 'mastg-storage-6-external-storage',
        ruleName: 'External Storage Usage Detected',
        severity: 'issue',
        description: 'App accesses external storage (SD card). Files written to external ' +
          'storage are world-readable by other apps with READ/WRITE_EXTERNAL_STORAGE ' +
          'permissions. On Android 10+ (API 29+), scoped storage restricts this, but ' +
          'legacy access methods may still expose data.',
        cwe: CWE,
        owasp: OWASP,
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: 'External storage APIs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
