/**
 * mSAS v2 — Task Affinity & Hijacking Scanner
 * MASTG Ref: MASTG-PLATFORM-5 (Task Hijacking)
 * CWE-926: Improper Export of Component
 */

var MSAS = MSAS || {};
MSAS.TaskAffinityScanner = (function() {
  'use strict';

  var CWE = 'CWE-926';
  var OWASP = 'M1';
  var MASVS = 'PLATFORM-5';

  var TASK_AFFINITY_SIGS = [
    'taskAffinity',
    'android:taskAffinity',
    'allowTaskReparenting',
    'android:allowTaskReparenting',
    'LAUNCH_MODE_SINGLE_TASK',
    'LAUNCH_MODE_SINGLE_INSTANCE',
    'singleTask',
    'singleInstance',
    'launchMode'
  ];

  var ACTIVITY_SIGS = [
    'Landroid/app/Activity',
    'Activity',
    'Landroid/app/Activity;->setFlags',
    'startActivity',
    'Landroid/content/Intent;->FLAG_ACTIVITY_NEW_TASK',
    'FLAG_ACTIVITY_NEW_TASK',
    'FLAG_ACTIVITY_CLEAR_TOP',
    'FLAG_ACTIVITY_SINGLE_TOP'
  ];

  var TASK_REORDER_SIGS = [
    'FLAG_ACTIVITY_REORDER_TO_FRONT',
    'FLAG_ACTIVITY_BROUGHT_TO_FRONT',
    'FLAG_ACTIVITY_RESET_TASK_IF_NEEDED',
    'FLAG_ACTIVITY_MULTIPLE_TASK',
    'moveTaskToFront'
  ];

  function scan(opts) {
    opts = opts || {};
    var strings = opts.strings || [];
    var findings = [];

    var hasTaskAffinity = MSAS.Utils.hasInStrings(strings, TASK_AFFINITY_SIGS);
    var hasActivity = MSAS.Utils.hasInStrings(strings, ACTIVITY_SIGS);
    var hasTaskReorder = MSAS.Utils.hasInStrings(strings, TASK_REORDER_SIGS);

    if (hasActivity) {
      findings.push({
        ruleId: 'mastg-platform-5-task-hijacking',
        ruleName: hasTaskAffinity
          ? '⚠️ Task Affinity / Task Hijacking Risk'
          : 'Activity Task Management',
        severity: hasTaskAffinity ? 'issue' : 'info',
        description: hasTaskAffinity
          ? 'App uses custom taskAffinity or singleTask/singleInstance launch modes. ' +
            'This configuration can enable StrandHogg-style task hijacking attacks ' +
            'where a malicious app with similar taskAffinity can overlay its own ' +
            'activity and steal user credentials. ' +
            (hasTaskReorder
              ? ' ⚠️ Task reordering flags also detected, increasing hijacking risk.'
              : ' Verify that activities with custom taskAffinity validate the caller.')
          : 'App uses standard Activity components. Standard launch modes are safe ' +
            'from task hijacking attacks.',
        cwe: hasTaskAffinity ? CWE : '',
        owasp: hasTaskAffinity ? OWASP : '',
        masvs: MASVS,
        file: 'classes.dex',
        line: null,
        match: hasTaskAffinity ? 'Task affinity risk' : 'Standard activities'
      });
    }

    if (!hasActivity) {
      findings.push({
        ruleId: 'mastg-platform-5-no-activity',
        ruleName: 'No Activity Task Management Detected',
        severity: 'info',
        description: 'No explicit activity launch mode or task management detected.',
        cwe: '',
        owasp: '',
        masvs: MASVS,
        file: '',
        line: null,
        match: 'No task management'
      });
    }

    return findings;
  }

  return { scan: scan };
})();
