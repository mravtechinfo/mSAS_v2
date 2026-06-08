/**
 * mSAS v2 — 3rd-Party Network SDK Audit Scanner
 * MASTG Ref: MASTG-NETWORK-5 (Third-Party Libraries)
 * CWE-1104: Use of Unmaintained Third-Party Components
 */

var MSAS = MSAS || {};
MSAS.NetworkSdkScanner = (function() {
  'use strict';

  var CWE = 'CWE-1104';
  var OWASP = 'M3';
  var MASVS = 'NETWORK-5';

  var NETWORK_LIBS = [
    { name: 'OkHttp', sigs: ['Lokhttp3/OkHttpClient', 'Lcom/squareup/okhttp/OkHttpClient', 'okhttp3', 'OkHttpClient'] },
    { name: 'Retrofit', sigs: ['Lretrofit2/Retrofit', 'Lcom/squareup/retrofit2/Retrofit', 'retrofit2', 'Retrofit.Builder'] },
    { name: 'Volley', sigs: ['Lcom/android/volley', 'Volley', 'RequestQueue', 'RequestFuture'] },
    { name: 'Ktor', sigs: ['Lio/ktor/client', 'ktor-client', 'io.ktor.client'] },
    { name: 'AFNetworking', sigs: ['AFNetworking', 'AFHTTPSessionManager', 'AFURLSessionManager'] },
    { name: 'Alamofire', sigs: ['Alamofire', 'SessionManager', 'Alamofire.Session'] },
    { name: 'NSURLSession', sigs: ['NSURLSession', 'NSURLConnection', 'NSMutableURLRequest'] },
    { name: 'Socket.IO', sigs: ['SocketIO', 'io.socket', 'SocketIOClient', 'Lcom/github/nkzawa/socketio'] },
    { name: 'MQTT', sigs: ['Lorg/eclipse/paho', 'MqttAndroidClient', 'MQTT', 'paho'] },
    { name: 'gRPC', sigs: ['Lio/grpc', 'grpc', 'Grpc'] },
    { name: 'Apache HTTP', sigs: ['Lorg/apache/http/impl/client', 'DefaultHttpClient', 'Lorg/apache/http/client/HttpClient'] },
    { name: 'NanoHTTPD', sigs: ['Lfi/iki/elonen/NanoHTTPD', 'NanoHTTPD'] }
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var detectedLibs = [];
    for (var i = 0; i < NETWORK_LIBS.length; i++) {
      if (MSAS.Utils.hasInStrings(strings, NETWORK_LIBS[i].sigs)) {
        detectedLibs.push(NETWORK_LIBS[i].name);
      }
    }

    if (detectedLibs.length > 0) {
      var isOutdated = detectedLibs.indexOf('Apache HTTP') >= 0 ||
                       detectedLibs.indexOf('NanoHTTPD') >= 0;

      findings.push({
        ruleId: 'mastg-network-5-network-sdks',
        ruleName: 'Network Library' + (detectedLibs.length > 1 ? 'ies' : '') + ' Detected',
        severity: isOutdated ? 'info' : 'secure',
        description: 'App uses ' + detectedLibs.length + ' network librar' +
          (detectedLibs.length > 1 ? 'ies' : 'y') + ': ' + detectedLibs.join(', ') + '. ' +
          (isOutdated
            ? '⚠️ Apache HTTP Client is deprecated in Android 6.0 (API 23) and ' +
              'removed in Android 9 (API 28). Migrate to OkHttp or HttpURLConnection.'
            : 'Verify all network libraries are up-to-date and not affected by known CVEs.'),
        cwe: isOutdated ? CWE : '',
        owasp: isOutdated ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: detectedLibs.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-network-5-no-network-sdks',
        ruleName: 'No Network Libraries Detected',
        severity: 'info',
        description: 'No major networking libraries detected. The app likely uses ' +
          'platform HTTP APIs directly (HttpURLConnection).',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No network libs'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
