/**
 * mSAS v2 — Native Code (NDK/JNI) Scanner
 * MASTG Ref: MASTG-CODE-4 (Native Code Analysis)
 * CWE-120: Buffer Overflow
 */

var MSAS = MSAS || {};
MSAS.NdkScanner = (function() {
  'use strict';

  var CWE = 'CWE-120';
  var OWASP = 'M7';
  var MASVS = 'CODE-4';

  var JNI_SIGS = [
    'Ljava/lang/System;->loadLibrary',
    'Ljava/lang/System;->load',
    'System.loadLibrary',
    'System.load',
    'Ldalvik/system/DexClassLoader',
    'Ldalvik/system/PathClassLoader',
    'Ldalvik/system/InMemoryDexClassLoader',
    'DexClassLoader',
    'PathClassLoader',
    'Ldalvik/system/DexFile',
    'DexFile'
  ];

  var NATIVE_METHOD_SIGS = [
    'native method',
    'nativeMethod',
    'registerNatives',
    'JNI_OnLoad',
    'JNI_OnUnload',
    'jint',
    'jstring',
    'jobject',
    'JNIEnv',
    'JavaVM'
  ];

  var UNSAFE_FUNCTIONS = [
    'memcpy',
    'strcpy',
    'strcat',
    'sprintf',
    'vsprintf',
    'gets',
    'scanf',
    'system',
    'popen',
    'execvp',
    'execve',
    'dlopen',
    'dlsym',
    'Ldalvik/system/Unsafe',
    'sun.misc.Unsafe',
    'Ljava/lang/Runtime;->exec',
    'Ljava/lang/ProcessBuilder'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasJNI = MSAS.Utils.hasInStrings(strings, JNI_SIGS);
    var hasNativeMethods = MSAS.Utils.hasInStrings(strings, NATIVE_METHOD_SIGS);
    var hasUnsafe = MSAS.Utils.hasInStrings(strings, UNSAFE_FUNCTIONS);

    if (hasJNI || hasNativeMethods) {
      findings.push({
        ruleId: 'mastg-code-4-native-code',
        ruleName: 'Native Code (JNI/NDK) Detected',
        severity: hasUnsafe ? 'issue' : 'info',
        description: 'App loads or uses native code libraries via JNI/NDK.' +
          (hasUnsafe
            ? ' ⚠️ Unsafe native functions detected (memcpy, strcpy, sprintf, ' +
              'gets). These can cause memory corruption and buffer overflow ' +
              'vulnerabilities. Consider using safe alternatives like strlcpy, ' +
              'snprintf, or C++ std::string.'
            : ' Verify that native code does not contain memory safety ' +
              'vulnerabilities. Native code in JNI exposes the app to buffer ' +
              'overflows, use-after-free, and other memory corruption bugs.'),
        cwe: hasUnsafe ? CWE : '',
        owasp: hasUnsafe ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: (hasJNI ? 'JNI' : '') +
          (hasNativeMethods ? (hasJNI ? ' + ' : '') + 'native methods' : '') +
          (hasUnsafe ? ' + unsafe functions' : '')
      });
    }

    if (!hasJNI && !hasNativeMethods) {
      findings.push({
        ruleId: 'mastg-code-4-no-native',
        ruleName: 'No Native Code Detected',
        severity: 'secure',
        description: 'No JNI/NDK native code loading detected. The app uses ' +
          'managed code only (Java/Kotlin).',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No native code'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
