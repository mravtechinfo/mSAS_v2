/**
 * mSAS v2 — OWASP Risk Matrix
 * 
 * 5x5 Likelihood × Impact heatmap with finding counts per cell.
 * Part of Phase 7: Reporting Suite (RPT-2).
 */

var MSAS = MSAS || {};

MSAS.RiskMatrix = (function() {
  'use strict';

  /**
   * Build a risk matrix from findings.
   * @param {Array} findings - Array of finding objects with { severity, cvss, category }
   * @returns {Object} { matrix, overall, distribution }
   */
  function compute(findings) {
    if (!findings || !findings.length) {
      return { matrix: emptyMatrix(), overall: 'None', distribution: {} };
    }

    // Map severity to impact level (1-5)
    var impactMap = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1
    };

    // Map CVSS score to likelihood (1-5)
    function likelihoodOf(cvss) {
      if (cvss >= 9.0) return 5;
      if (cvss >= 7.0) return 4;
      if (cvss >= 4.0) return 3;
      if (cvss >= 1.0) return 2;
      return 1;
    }

    var matrix = emptyMatrix();
    var distribution = {};
    var totalWeighted = 0;
    var totalCount = 0;

    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      if (f.passed) continue;

      var impact = impactMap[f.severity] || 1;
      var like = likelihoodOf(f.cvss || 0);
      
      var cell = matrix[like - 1][impact - 1];
      cell.count++;
      cell.findings.push(f.title || f.ruleName || 'Unknown');
      totalWeighted += like * impact;
      totalCount++;
    }

    // Determine overall risk
    var avgWeight = totalCount > 0 ? totalWeighted / totalCount : 0;
    var overall = 'Low';
    if (avgWeight >= 20) overall = 'Critical';
    else if (avgWeight >= 12) overall = 'High';
    else if (avgWeight >= 6) overall = 'Medium';

    // Distribution counts
    distribution = {
      critical: findings.filter(function(f) { return f.severity === 'critical' && !f.passed; }).length,
      high:     findings.filter(function(f) { return f.severity === 'high' && !f.passed; }).length,
      medium:   findings.filter(function(f) { return f.severity === 'medium' && !f.passed; }).length,
      low:      findings.filter(function(f) { return f.severity === 'low' && !f.passed; }).length,
      info:     findings.filter(function(f) { return f.severity === 'info' && !f.passed; }).length
    };

    return { matrix: matrix, overall: overall, distribution: distribution, total: totalCount };
  }

  function emptyMatrix() {
    var m = [];
    for (var row = 0; row < 5; row++) {
      m[row] = [];
      for (var col = 0; col < 5; col++) {
        m[row][col] = { count: 0, findings: [] };
      }
    }
    return m;
  }

  /**
   * Returns CSS class for a risk level.
   */
  function riskClass(like, impact) {
    var product = (like + 1) * (impact + 1);
    if (product >= 25) return 'risk-critical';
    if (product >= 16) return 'risk-high';
    if (product >= 9)  return 'risk-medium';
    if (product >= 4)  return 'risk-low';
    return 'risk-info';
  }

  /**
   * Returns severity label for a risk level.
   */
  function riskLabel(like, impact) {
    var product = (like + 1) * (impact + 1);
    if (product >= 25) return 'Critical';
    if (product >= 16) return 'High';
    if (product >= 9)  return 'Medium';
    if (product >= 4)  return 'Low';
    return 'Info';
  }

  /**
   * Render risk matrix to HTML table.
   * @param {Object} computed - Result from compute()
   * @returns {string} HTML string
   */
  function renderHtml(computed) {
    if (!computed || !computed.matrix) return '<div class="no-data">No risk data available.</div>';

    var likelihoodLabels = ['Very Low', 'Low', 'Medium', 'High', 'Very High'];
    var impactLabels = ['Very Low', 'Low', 'Medium', 'High', 'Very High'];

    var html = '<div class="risk-matrix-container">';
    
    // Overall risk badge
    html += '<div class="risk-overall">';
    html += '  <span class="risk-overall-label">Overall Risk Level</span>';
    html += '  <span class="risk-overall-value risk-' + computed.overall.toLowerCase() + '">' + computed.overall + '</span>';
    html += '</div>';

    // Severity distribution
    if (computed.distribution) {
      html += '<div class="risk-distribution">';
      html += '  <span class="risk-dist-label">Severity Breakdown</span>';
      html += '  <div class="risk-dist-bars">';
      var sevs = ['critical', 'high', 'medium', 'low', 'info'];
      var colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6' };
      var maxCount = Math.max(1, computed.distribution.critical, computed.distribution.high, 
                               computed.distribution.medium, computed.distribution.low);
      for (var s = 0; s < sevs.length; s++) {
        var sev = sevs[s];
        var count = computed.distribution[sev] || 0;
        var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
        html += '<div class="risk-dist-bar">';
        html += '  <span class="risk-dist-bar-label">' + sev.charAt(0).toUpperCase() + sev.slice(1) + '</span>';
        html += '  <div class="risk-dist-bar-track"><div class="risk-dist-bar-fill" style="width:' + pct + '%;background:' + colors[sev] + '"></div></div>';
        html += '  <span class="risk-dist-bar-count">' + count + '</span>';
        html += '</div>';
      }
      html += '  </div>';
      html += '</div>';
    }

    // The 5x5 matrix
    html += '<table class="risk-matrix-table" role="grid" aria-label="Risk Matrix: Likelihood × Impact">';
    html += '<caption class="sr-only">5x5 risk matrix showing likelihood vs impact heatmap</caption>';
    html += '<thead><tr><th class="corner"></th>';
    for (var c = 0; c < 5; c++) {
      html += '<th scope="col"><span class="axis-label">' + impactLabels[c] + '</span><span class="axis-sub-label">Impact</span></th>';
    }
    html += '</tr></thead><tbody>';
    for (var r = 4; r >= 0; r--) {
      html += '<tr>';
      html += '<th scope="row"><span class="axis-label">' + likelihoodLabels[r] + '</span><span class="axis-sub-label">Likelihood</span></th>';
      for (var c2 = 0; c2 < 5; c2++) {
        var cell = computed.matrix[r][c2] || { count: 0, findings: [] };
        var cls = riskClass(r, c2);
        var label = riskLabel(r, c2);
        html += '<td class="risk-cell ' + cls + '" data-count="' + cell.count + '" data-risk="' + label.toLowerCase() + '">';
        html += '  <div class="risk-cell-count">' + cell.count + '</div>';
        html += '  <div class="risk-cell-label">' + label + '</div>';
        if (cell.findings.length > 0) {
          html += '  <div class="risk-cell-findings">' + cell.findings.slice(0, 3).join(', ') + (cell.findings.length > 3 ? '…' : '') + '</div>';
        }
        html += '</td>';
      }
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';

    return html;
  }

  return {
    compute: compute,
    renderHtml: renderHtml,
    riskClass: riskClass,
    riskLabel: riskLabel
  };
})();
