/**
 * mSAS v2 — Unified Findings Dashboard
 * 
 * Aggregated metrics, MASTG coverage, severity distribution, pass/fail rates.
 * Part of Phase 7: Reporting Suite (RPT-4).
 */

var MSAS = MSAS || {};

MSAS.Dashboard = (function() {
  'use strict';

  /**
   * Compute dashboard metrics from analysis results.
   * @param {Object} results - Analysis results with findings
   * @param {Object} options - { appName, auditorType, scanDuration }
   * @returns {Object} Dashboard data
   */
  function computeMetrics(results, options) {
    options = options || {};
    var findings = extractFindings(results);
    var summary = results.summary || {};
    
    var totalV2Findings = 0;
    var v2Findings = [];

    // Gather all v2 findings from results
    for (var key in results) {
      if (key.indexOf('v2_') === 0 || key.indexOf('msas_') === 0) {
        var group = results[key];
        if (Array.isArray(group)) {
          v2Findings = v2Findings.concat(group);
        }
      }
    }

    // Get all findings from groupedFindings too
    if (results.groupedFindings) {
      var sevs = ['issue', 'info', 'secure'];
      for (var s = 0; s < sevs.length; s++) {
        var gf = results.groupedFindings[sevs[s]];
        if (Array.isArray(gf)) {
          // Merge but deduplicate by ruleId
          for (var g = 0; g < gf.length; g++) {
            var existing = false;
            for (var v = 0; v < v2Findings.length; v++) {
              if (v2Findings[v].ruleId === gf[g].ruleId) {
                existing = true;
                break;
              }
            }
            if (!existing) v2Findings.push(gf[g]);
          }
        }
      }
    }

    totalV2Findings = v2Findings.length;

    // Severity distribution
    var severityDist = { critical: 0, high: 0, medium: 0, low: 0, info: 0, secure: 0 };
    var categoryDist = {};
    var masvsCoverage = {};

    for (var f = 0; f < v2Findings.length; f++) {
      var finding = v2Findings[f];
      var sev = finding.severity || 'info';
      if (sev === 'issue') sev = 'high';
      if (severityDist[sev] !== undefined) severityDist[sev]++;
      else severityDist[sev] = 1;

      var cat = finding.category || finding.masvs || 'uncategorized';
      categoryDist[cat] = (categoryDist[cat] || 0) + 1;

      var masvs = finding.masvs || '';
      if (masvs) {
        masvsCoverage[masvs] = (masvsCoverage[masvs] || 0) + 1;
      }
    }

    // Compute security score
    var totalChecks = v2Findings.length || 1;
    var issueCount = (summary.issue || 0) + (severityDist.critical || 0) + (severityDist.high || 0);
    var score = Math.max(0, Math.min(100, 100 - (issueCount / totalChecks) * 100));
    var grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 55 ? 'C' : score >= 35 ? 'D' : 'F';

    return {
      appName: options.appName || results.appInfo?.appLabel || results.appInfo?.packageName || 'Unknown',
      auditorType: options.auditorType || 'APK',
      scanTimestamp: new Date().toISOString(),
      scanDuration: options.scanDuration || 0,
      totalFindings: totalV2Findings,
      severityDist: severityDist,
      categoryDist: categoryDist,
      masvsCoverage: masvsCoverage,
      masvsCoverageCount: Object.keys(masvsCoverage).length,
      securityScore: Math.round(score),
      securityGrade: grade,
      issueCount: issueCount,
      summary: summary
    };
  }

  /**
   * Extract findings from various result structures.
   */
  function extractFindings(results) {
    if (!results) return [];
    var all = [];
    
    // New v2 format (flat array on results)
    if (Array.isArray(results.findings)) {
      all = all.concat(results.findings);
    }
    // v1 groupedFindings format
    if (results.groupedFindings) {
      var sevs = ['issue', 'info', 'secure'];
      for (var s = 0; s < sevs.length; s++) {
        if (Array.isArray(results.groupedFindings[sevs[s]])) {
          all = all.concat(results.groupedFindings[sevs[s]]);
        }
      }
    }
    return all;
  }

  /**
   * Render dashboard HTML.
   * @param {Object} metrics - Result from computeMetrics()
   * @returns {string} HTML string
   */
  function renderHtml(metrics) {
    if (!metrics) return '<div class="no-data">No metrics available.</div>';

    var html = '<div class="dashboard-container">';

    // Header
    html += '<div class="dashboard-header">';
    html += '  <h3 class="dashboard-title">Security Dashboard</h3>';
    html += '  <div class="dashboard-meta">';
    html += '    <span class="dashboard-meta-item">' + esc(metrics.appName) + '</span>';
    html += '    <span class="dashboard-meta-item">' + metrics.auditorType + ' Audit</span>';
    html += '    <span class="dashboard-meta-item">' + formatDate(metrics.scanTimestamp) + '</span>';
    if (metrics.scanDuration) {
      html += '    <span class="dashboard-meta-item">' + (metrics.scanDuration / 1000).toFixed(1) + 's</span>';
    }
    html += '  </div>';
    html += '</div>';

    // Score card
    var scoreClass = metrics.securityScore >= 80 ? 'good' : metrics.securityScore >= 55 ? 'ok' : 'bad';
    html += '<div class="dashboard-score-card ' + scoreClass + '">';
    html += '  <div class="dashboard-score-value">' + metrics.securityScore + '</div>';
    html += '  <div class="dashboard-score-grade">Grade ' + metrics.securityGrade + '</div>';
    html += '  <div class="dashboard-score-desc">Security Score</div>';
    html += '</div>';

    // Summary grid
    html += '<div class="dashboard-grid">';
    html += '  <div class="dashboard-stat"><span class="dashboard-stat-value">' + metrics.totalFindings + '</span><span class="dashboard-stat-label">Total Findings</span></div>';
    html += '  <div class="dashboard-stat"><span class="dashboard-stat-value accent">' + metrics.issueCount + '</span><span class="dashboard-stat-label">Issues</span></div>';
    html += '  <div class="dashboard-stat"><span class="dashboard-stat-value blue">' + metrics.masvsCoverageCount + '</span><span class="dashboard-stat-label">MASTG Refs</span></div>';
    html += '  <div class="dashboard-stat"><span class="dashboard-stat-value green">' + (metrics.summary?.secure || 0) + '</span><span class="dashboard-stat-label">Passed Checks</span></div>';
    html += '</div>';

    // Severity distribution bars
    html += '<div class="dashboard-section"><h4>Severity Distribution</h4>';
    html += '<div class="dashboard-bars">';
    var sevs = [
      { key: 'critical', label: 'Critical', color: '#ef4444' },
      { key: 'high',     label: 'High',     color: '#f97316' },
      { key: 'medium',   label: 'Medium',   color: '#eab308' },
      { key: 'low',      label: 'Low',      color: '#22c55e' },
      { key: 'info',     label: 'Info',     color: '#3b82f6' },
      { key: 'secure',   label: 'Secure',   color: '#6366f1' }
    ];
    var maxCount = Math.max(1, metrics.severityDist.critical || 0, metrics.severityDist.high || 0,
                             metrics.severityDist.medium || 0, metrics.severityDist.low || 0,
                             metrics.severityDist.info || 0, metrics.severityDist.secure || 0);
    for (var s = 0; s < sevs.length; s++) {
      var sev = sevs[s];
      var count = metrics.severityDist[sev.key] || 0;
      var pct = maxCount > 0 ? (count / maxCount * 100) : 0;
      html += '<div class="dashboard-bar-row">';
      html += '  <span class="dashboard-bar-label">' + sev.label + '</span>';
      html += '  <div class="dashboard-bar-track"><div class="dashboard-bar-fill" style="width:' + pct + '%;background:' + sev.color + '"></div></div>';
      html += '  <span class="dashboard-bar-count">' + count + '</span>';
      html += '</div>';
    }
    html += '</div></div>';

    // Category distribution
    var cats = Object.keys(metrics.categoryDist).sort(function(a, b) {
      return metrics.categoryDist[b] - metrics.categoryDist[a];
    }).slice(0, 10);
    if (cats.length > 0) {
      html += '<div class="dashboard-section"><h4>Top Categories</h4>';
      html += '<div class="dashboard-cats">';
      var maxCat = Math.max(1, cats.reduce(function(m, c) { return Math.max(m, metrics.categoryDist[c]); }, 0));
      for (var c2 = 0; c2 < cats.length; c2++) {
        var cat = cats[c2];
        var pct2 = (metrics.categoryDist[cat] / maxCat) * 100;
        html += '<div class="dashboard-cat-row">';
        html += '  <span class="dashboard-cat-label">' + esc(cat) + '</span>';
        html += '  <div class="dashboard-cat-track"><div class="dashboard-cat-fill" style="width:' + pct2 + '%"></div></div>';
        html += '  <span class="dashboard-cat-count">' + metrics.categoryDist[cat] + '</span>';
        html += '</div>';
      }
      html += '</div></div>';
    }

    html += '</div>'; // .dashboard-container
    return html;
  }

  function esc(str) {
    if (str == null) return '';
    var d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function formatDate(iso) {
    if (!iso) return '';
    try {
      var d = new Date(iso);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString();
    } catch (_) {
      return iso;
    }
  }

  return {
    computeMetrics: computeMetrics,
    renderHtml: renderHtml
  };
})();
