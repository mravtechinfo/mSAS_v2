/**
 * mSAS v2 — CVSS 3.1 Calculator
 * 
 * Full CVSS 3.1 vector parsing and scoring engine.
 * Computes base, temporal, and environmental scores.
 * Part of Phase 7: Reporting Suite (RPT-1).
 */

var MSAS = MSAS || {};

MSAS.CVSS = (function() {
  'use strict';

  // ── CVSS 3.1 Metric Definitions ──────────────────────────────────────────

  var BASE_METRICS = {
    AV: { label: 'Attack Vector', values: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 } },
    AC: { label: 'Attack Complexity', values: { L: 0.77, H: 0.44 } },
    PR: { label: 'Privileges Required', values: { N: 0.85, L: 0.68, H: 0.5 } },
    UI: { label: 'User Interaction', values: { N: 0.85, R: 0.62 } },
    S:  { label: 'Scope', values: { U: 'unchanged', C: 'changed' } },
    C:  { label: 'Confidentiality', values: { H: 0.56, L: 0.22, N: 0 } },
    I:  { label: 'Integrity', values: { H: 0.56, L: 0.22, N: 0 } },
    A:  { label: 'Availability', values: { H: 0.56, L: 0.22, N: 0 } }
  };

  var TEMPORAL_METRICS = {
    E:  { label: 'Exploit Code Maturity', values: { X: 1, H: 1, F: 0.97, P: 0.94, U: 0.91 } },
    RL: { label: 'Remediation Level', values: { X: 1, U: 1, W: 0.97, T: 0.96, O: 0.95 } },
    RC: { label: 'Report Confidence', values: { X: 1, C: 1, R: 0.96, U: 0.92 } }
  };

  var ENVIRONMENTAL_METRICS = {
    CR: { label: 'Confidentiality Requirement', values: { X: 1, H: 1.5, M: 1, L: 0.5 } },
    IR: { label: 'Integrity Requirement', values: { X: 1, H: 1.5, M: 1, L: 0.5 } },
    AR: { label: 'Availability Requirement', values: { X: 1, H: 1.5, M: 1, L: 0.5 } }
  };

  // Modified base metrics for environmental scoring
  var MODIFIED_BASE_METRICS = {
    MAV: { values: { X: 1, N: 0.85, A: 0.62, L: 0.55, P: 0.2 } },
    MAC: { values: { X: 1, L: 0.77, H: 0.44 } },
    MPR: { values: { X: 1, N: 0.85, L: 0.68, H: 0.5 } },
    MUI: { values: { X: 1, N: 0.85, R: 0.62 } },
    MS:  { values: { X: 'unchanged', U: 'unchanged', C: 'changed' } },
    MC:  { values: { X: 1, H: 0.56, L: 0.22, N: 0 } },
    MI:  { values: { X: 1, H: 0.56, L: 0.22, N: 0 } },
    MA:  { values: { X: 1, H: 0.56, L: 0.22, N: 0 } }
  };

  // ── Vector Parsing ────────────────────────────────────────────────────────

  /**
   * Parses a CVSS 3.1 vector string into a metrics object.
   * @param {string} vector - e.g., "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
   * @returns {Object|null} Parsed metrics or null on failure
   */
  function parseVector(vector) {
    if (!vector || typeof vector !== 'string') return null;
    
    var v = vector.trim();
    if (v.indexOf('CVSS:3.1') !== 0 && v.indexOf('CVSS:3.0') !== 0) {
      // Try without prefix
      if (v.indexOf('/') < 0) return null;
    }

    var parts = v.split('/');
    var metrics = {};
    
    for (var i = 0; i < parts.length; i++) {
      var part = parts[i].trim();
      if (part.indexOf('CVSS:') === 0) {
        metrics._version = part;
        continue;
      }
      var eqIdx = part.indexOf(':');
      if (eqIdx < 0) continue;
      var key = part.substring(0, eqIdx).toUpperCase();
      var val = part.substring(eqIdx + 1).toUpperCase();
      
      // Validate against known metrics
      if (BASE_METRICS[key] && BASE_METRICS[key].values[val] !== undefined) {
        metrics[key] = val;
      } else if (TEMPORAL_METRICS[key] && TEMPORAL_METRICS[key].values[val] !== undefined) {
        metrics[key] = val;
      } else if (ENVIRONMENTAL_METRICS[key] && ENVIRONMENTAL_METRICS[key].values[val] !== undefined) {
        metrics[key] = val;
      } else if (MODIFIED_BASE_METRICS[key] && MODIFIED_BASE_METRICS[key].values[val] !== undefined) {
        metrics[key] = val;
      }
    }

    // Validate required base metrics
    var required = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];
    for (var j = 0; j < required.length; j++) {
      if (!metrics[required[j]]) return null;
    }

    return metrics;
  }

  // ── Scoring Functions ─────────────────────────────────────────────────────

  /**
   * Calculate base score from metrics.
   * @param {Object} m - Parsed metrics
   * @returns {number} CVSS base score 0-10
   */
  function baseScore(m) {
    if (!m) return 0;

    var av = BASE_METRICS.AV.values[m.AV];
    var ac = BASE_METRICS.AC.values[m.AC];
    var pr = BASE_METRICS.PR.values[m.PR];
    // In CVSS 3.1, PR values are the same regardless of Scope: N=0.85, L=0.68, H=0.50
    if (m.S === 'C') pr = m.PR === 'N' ? 0.85 : m.PR === 'L' ? 0.68 : 0.5;
    var ui = BASE_METRICS.UI.values[m.UI];
    var c  = BASE_METRICS.C.values[m.C];
    var i  = BASE_METRICS.I.values[m.I];
    var a  = BASE_METRICS.A.values[m.A];

    var impactBase = 1 - ((1 - c) * (1 - i) * (1 - a));
    var scopeChanged = m.S === 'C';
    var impact = scopeChanged 
      ? 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15)
      : 6.42 * impactBase;
    
    if (impact <= 0) return 0;

    var exploitability = 8.22 * av * ac * pr * ui;
    var base = scopeChanged 
      ? Math.min(1.08 * (impact + exploitability), 10) 
      : Math.min(impact + exploitability, 10);

    return roundTo1(base);
  }

  /**
   * Calculate temporal score.
   * @param {Object} m - Parsed metrics (with temporal)
   * @returns {number} CVSS temporal score 0-10
   */
  function temporalScore(m) {
    if (!m) return 0;
    var base = baseScore(m);
    var e  = m.E  ? TEMPORAL_METRICS.E.values[m.E] : 1;
    var rl = m.RL ? TEMPORAL_METRICS.RL.values[m.RL] : 1;
    var rc = m.RC ? TEMPORAL_METRICS.RC.values[m.RC] : 1;
    return roundTo1(base * e * rl * rc);
  }

  /**
   * Calculate environmental score.
   * @param {Object} m - Parsed metrics (with environmental)
   * @returns {number} CVSS environmental score 0-10
   */
  function environmentalScore(m) {
    if (!m) return 0;

    // Modified base metrics
    var mav = m.MAV ? MODIFIED_BASE_METRICS.MAV.values[m.MAV] : BASE_METRICS.AV.values[m.AV];
    var mac = m.MAC ? MODIFIED_BASE_METRICS.MAC.values[m.MAC] : BASE_METRICS.AC.values[m.AC];
    var mpr = m.MPR ? MODIFIED_BASE_METRICS.MPR.values[m.MPR] : BASE_METRICS.PR.values[m.PR];
    var mui = m.MUI ? MODIFIED_BASE_METRICS.MUI.values[m.MUI] : BASE_METRICS.UI.values[m.UI];
    var ms  = m.MS ? MODIFIED_BASE_METRICS.MS.values[m.MS] : BASE_METRICS.S.values[m.S];
    var mc  = m.MC ? MODIFIED_BASE_METRICS.MC.values[m.MC] : BASE_METRICS.C.values[m.C];
    var mi  = m.MI ? MODIFIED_BASE_METRICS.MI.values[m.MI] : BASE_METRICS.I.values[m.I];
    var ma  = m.MA ? MODIFIED_BASE_METRICS.MA.values[m.MA] : BASE_METRICS.A.values[m.A];

    // Security requirements
    var cr = m.CR ? ENVIRONMENTAL_METRICS.CR.values[m.CR] : 1;
    var ir = m.IR ? ENVIRONMENTAL_METRICS.IR.values[m.IR] : 1;
    var ar = m.AR ? ENVIRONMENTAL_METRICS.AR.values[m.AR] : 1;

    // In CVSS 3.1, PR values are the same regardless of Scope: N=0.85, L=0.68, H=0.50
    // The original non-modified PR values already handle this correctly.

    var impactBase = Math.min(1 - ((1 - mc * cr) * (1 - mi * ir) * (1 - ma * ar)), 0.915);
    var scopeChanged = ms === 'C';
    var impact = scopeChanged 
      ? 7.52 * (impactBase - 0.029) - 3.25 * Math.pow(impactBase - 0.02, 15)
      : 6.42 * impactBase;

    if (impact <= 0) return 0;

    var exploitability = 8.22 * mav * mac * mpr * mui;

    var e   = m.E  ? TEMPORAL_METRICS.E.values[m.E] : 1;
    var rl  = m.RL ? TEMPORAL_METRICS.RL.values[m.RL] : 1;
    var rc  = m.RC ? TEMPORAL_METRICS.RC.values[m.RC] : 1;

    var score = scopeChanged
      ? Math.min(1.08 * (impact + exploitability), 10)
      : Math.min(impact + exploitability, 10);

    score = score * e * rl * rc;

    return roundTo1(score);
  }

  /**
   * Calculate all scores from a vector.
   * @param {string} vector - CVSS 3.1 vector
   * @returns {Object} { base, temporal, environmental, vector, parsed, severity }
   */
  function score(vector) {
    var m = parseVector(vector);
    if (!m) return null;

    var base = baseScore(m);
    var temporal = temporalScore(m);
    var env = environmentalScore(m);

    return {
      vector: vector,
      parsed: m,
      base: base,
      temporal: temporal,
      environmental: env,
      severity: MSAS.TestResult ? MSAS.TestResult.severityOf(base) : severityOf(base)
    };
  }

  /**
   * Generate a CVSS 3.1 vector from metric values.
   * @param {Object} metrics - Metric key-value pairs
   * @returns {string} CVSS vector string
   */
  function buildVector(metrics) {
    var parts = ['CVSS:3.1'];
    var order = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A',
                 'E', 'RL', 'RC', 'CR', 'IR', 'AR',
                 'MAV', 'MAC', 'MPR', 'MUI', 'MS', 'MC', 'MI', 'MA'];
    
    for (var i = 0; i < order.length; i++) {
      var k = order[i];
      if (metrics[k]) {
        parts.push(k + ':' + metrics[k]);
      }
    }
    return parts.join('/');
  }

  /**
   * Guesses a vector from a severity level for quick scoring.
   * @param {string} severity - 'critical', 'high', 'medium', 'low', 'info'
   * @returns {string} Approximate CVSS vector
   */
  function guessVector(severity) {
    var vectors = {
      critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      high:     'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L',
      medium:   'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L',
      low:      'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N',
      info:     'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N'
    };
    return vectors[severity] || vectors.info;
  }

  /**
   * Returns human-readable severity label.
   */
  function severityOf(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score >= 1.0) return 'low';
    return 'info';
  }

  /**
   * Describe what a CVSS score means.
   */
  function describeScore(score) {
    var s = severityOf(score);
    var descriptions = {
      critical: 'Exploitation is straightforward and likely to result in total compromise.',
      high:     'Exploitation is likely and could result in significant damage.',
      medium:   'Exploitation requires some conditions but could be serious.',
      low:      'Exploitation is difficult or impact is limited.',
      info:     'Negligible security impact.'
    };
    return descriptions[s] || '';
  }

  function roundTo1(num) {
    return Math.round(num * 10) / 10;
  }

  // ── Public API ────────────────────────────────────────────────────────────

  return {
    parseVector: parseVector,
    baseScore: baseScore,
    temporalScore: temporalScore,
    environmentalScore: environmentalScore,
    score: score,
    buildVector: buildVector,
    guessVector: guessVector,
    severityOf: severityOf,
    describeScore: describeScore,
    METRICS: {
      base: BASE_METRICS,
      temporal: TEMPORAL_METRICS,
      environmental: ENVIRONMENTAL_METRICS,
      modified: MODIFIED_BASE_METRICS
    }
  };
})();
