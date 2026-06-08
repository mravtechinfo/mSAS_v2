/**
 * mSAS v2 — Anti-Debugging Detection Scanner
 * MASTG Ref: MASTG-RESILIENCE-2 (Anti-Debugging)
 * CWE-1063: Insufficient Protection Against Debugging
 */

var MSAS = MSAS || {};
MSAS.AntiDebugScanner = (function() {
  'use strict';

  var CWE = 'CWE-1063';
  var OWASP = 'M8';
  var MASVS = 'RESILIENCE-2';

  var DEBUGGER_SIGS = [
    'Landroid/os/Debug;->isDebuggerConnected',
    'Landroid/os/Debug;->waitingForDebugger',
    'isDebuggerConnected',
    'waitingForDebugger',
    'android.os.Debug.isDebuggerConnected',
    'Debug.waitingForDebugger',
    'android:debuggable'
  ];

  var TRACER_PID_SIGS = [
    'TracerPid',
    '/proc/self/status',
    '/proc/self/cmdline',
    '/proc/stat',
    'tracerPid',
    'getTracerPid'
  ];

  var PT_SIGS = [
    'ptrace',
    'PTRACE_TRACEME',
    'PT_DENY_ATTACH',
    'syscall',
    'prctl',
    'SIGTRAP'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasDebugger = MSAS.Utils.hasInStrings(strings, DEBUGGER_SIGS);
    var hasTracer = MSAS.Utils.hasInStrings(strings, TRACER_PID_SIGS);
    var hasPT = MSAS.Utils.hasInStrings(strings, PT_SIGS);

    var hasAnyAntiDebug = hasDebugger || hasTracer || hasPT;

    if (hasAnyAntiDebug) {
      var methods = [];
      if (hasDebugger) methods.push('isDebuggerConnected');
      if (hasTracer) methods.push('TracerPid check');
      if (hasPT) methods.push('ptrace/PT_DENY_ATTACH');

      findings.push({
        ruleId: 'mastg-resilience-2-anti-debug',
        ruleName: 'Anti-Debugging Protection Detected',
        severity: 'secure',
        description: 'App implements anti-debugging protection via: ' +
          methods.join(', ') + '. These checks make dynamic analysis more ' +
          'difficult. Verify they are placed in security-critical code paths.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: methods.join(', ')
      });
    } else {
      findings.push({
        ruleId: 'mastg-resilience-2-no-anti-debug',
        ruleName: 'No Anti-Debugging Protection',
        severity: 'info',
        description: 'No anti-debugging protection detected. Consider adding ' +
          'debugger detection for apps handling sensitive data.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No anti-debugging'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
