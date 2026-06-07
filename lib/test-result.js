/**
 * mSAS v2 — Standardized TestResult Schema
 * 
 * Unified finding schema used across APK, IPA, and ADB auditors.
 * CVSS 3.1 aligned severity model.
 * 
 * Usage:
 *   var result = MSAS.TestResult.create({ ... });
 *   MSAS.TestResult.severityOf(9.5); // 'critical'
 */

var MSAS = MSAS || {};

MSAS.TestResult = (function() {
  'use strict';

  /**
   * Severity thresholds aligned with CVSS 3.1
   */
  var SEVERITY = {
    CRITICAL: { min: 9.0, max: 10.0, label: 'critical',  score: 10 },
    HIGH:     { min: 7.0, max: 8.9,  label: 'high',      score: 8  },
    MEDIUM:   { min: 4.0, max: 6.9,  label: 'medium',    score: 5  },
    LOW:      { min: 1.0, max: 3.9,  label: 'low',       score: 2  },
    INFO:     { min: 0.0, max: 0.9,  label: 'info',      score: 0  }
  };

  /**
   * Valid categories for filtering and grouping
   */
  var CATEGORIES = {
    STORAGE:     'storage',
    CRYPTO:      'cryptography',
    AUTH:        'authentication',
    NETWORK:     'network',
    PLATFORM:    'platform',
    CODE:        'code_quality',
    RESILIENCE:  'resilience',
    AI_ML:       'ai_ml',
    ADB:         'adb',
    CONFIG:      'configuration',
    PERMISSIONS: 'permissions',
    SECRETS:     'secrets',
    GENERAL:     'general'
  };

  /**
   * Creates a standardized test result
   * 
   * @param {Object} opts
   * @param {string}  opts.id          - Unique identifier (e.g., 'mastg-storage-1-sqlite')
   * @param {string}  opts.title       - Short title
   * @param {string}  opts.description - Detailed description of the finding
   * @param {number}  opts.cvss        - CVSS 3.1 score (0-10)
   * @param {string}  opts.category    - Category from CATEGORIES
   * @param {string}  [opts.mastgRef]  - MASTG reference (e.g., 'MASTG-STORAGE-1')
   * @param {string}  [opts.remediation] - How to fix the issue
   * @param {string}  [opts.detail]    - Extra detail/snippet from analysis
   * @param {boolean} [opts.passed]    - Whether this check passed (default: false means finding)
   * @returns {Object} standardized result
   */
  function create(opts) {
    opts = opts || {};
    var cvss = clampScore(opts.cvss || 0);
    return {
      id:          opts.id || 'msas-' + Date.now(),
      title:       opts.title || 'Untitled Finding',
      description: opts.description || '',
      severity:    severityOf(cvss),
      cvss:        cvss,
      category:    opts.category || CATEGORIES.GENERAL,
      mastgRef:    opts.mastgRef || '',
      remediation: opts.remediation || '',
      detail:      opts.detail || '',
      passed:      opts.passed === true,
      timestamp:   new Date().toISOString()
    };
  }

  /**
   * Returns the severity label for a CVSS score
   * @param {number} score - CVSS 3.1 score 0-10
   * @returns {string} 'critical' | 'high' | 'medium' | 'low' | 'info'
   */
  function severityOf(score) {
    score = clampScore(score);
    if (score >= SEVERITY.CRITICAL.min) return SEVERITY.CRITICAL.label;
    if (score >= SEVERITY.HIGH.min)     return SEVERITY.HIGH.label;
    if (score >= SEVERITY.MEDIUM.min)   return SEVERITY.MEDIUM.label;
    if (score >= SEVERITY.LOW.min)      return SEVERITY.LOW.label;
    return SEVERITY.INFO.label;
  }

  /**
   * Returns the numeric score for a severity label
   * @param {string} label - severity label
   * @returns {number} numeric score 0-10
   */
  function scoreOf(label) {
    for (var key in SEVERITY) {
      if (SEVERITY[key].label === label) return SEVERITY[key].score;
    }
    return 0;
  }

  /**
   * Clamps a CVSS score between 0 and 10
   */
  function clampScore(score) {
    return Math.max(0, Math.min(10, typeof score === 'number' ? score : 0));
  }

  /**
   * Returns a CSS class for the severity level
   */
  function severityClass(label) {
    var map = {
      critical: 'severity-critical',
      high:     'severity-high',
      medium:   'severity-medium',
      low:      'severity-low',
      info:     'severity-info'
    };
    return map[label] || 'severity-info';
  }

  return {
    create:         create,
    severityOf:     severityOf,
    scoreOf:        scoreOf,
    severityClass:  severityClass,
    CATEGORIES:     CATEGORIES,
    SEVERITY:       SEVERITY
  };
})();
