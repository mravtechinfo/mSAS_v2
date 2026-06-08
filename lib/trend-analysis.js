/**
 * mSAS v2 — Severity Trend Analysis
 * 
 * Track findings over multiple scans, compare between versions.
 * Part of Phase 7: Reporting Suite (RPT-9).
 */

var MSAS = MSAS || {};

MSAS.TrendAnalysis = (function() {
  'use strict';

  /**
   * Compute trend data from scan history.
   * @param {Array} scans - Array of scan records from ScanHistory
   * @returns {Object} { trends, scoreHistory, findingsHistory, comparison }
   */
  function compute(scans) {
    if (!scans || scans.length === 0) {
      return { trends: [], scoreHistory: [], findingsHistory: [], comparison: null };
    }

    // Sort by timestamp ascending
    var sorted = scans.slice().sort(function(a, b) {
      return new Date(a.timestamp) - new Date(b.timestamp);
    });

    var scoreHistory = sorted.map(function(s) {
      return {
        date: s.timestamp,
        score: s.score || 0,
        label: s.appName || s.name || 'Unknown'
      };
    });

    var findingsHistory = sorted.map(function(s) {
      var dist = s.severityDist || {};
      return {
        date: s.timestamp,
        issues: dist.issue || 0,
        info: dist.info || 0,
        secure: dist.secure || 0,
        total: (dist.issue || 0) + (dist.info || 0) + (dist.secure || 0)
      };
    });

    // Trend direction
    var trends = [];
    if (sorted.length >= 2) {
      var latest = sorted[sorted.length - 1];
      var prev = sorted[sorted.length - 2];
      var scoreDiff = (latest.score || 0) - (prev.score || 0);
      var findingDiff = (latest.severityDist?.issue || 0) - (prev.severityDist?.issue || 0);

      trends.push({
        metric: 'Security Score',
        current: latest.score || 0,
        previous: prev.score || 0,
        diff: scoreDiff,
        direction: scoreDiff > 0 ? 'up' : scoreDiff < 0 ? 'down' : 'stable',
        improved: scoreDiff > 0
      });

      trends.push({
        metric: 'Issues Found',
        current: latest.severityDist?.issue || 0,
        previous: prev.severityDist?.issue || 0,
        diff: findingDiff,
        direction: findingDiff < 0 ? 'up' : findingDiff > 0 ? 'down' : 'stable',
        improved: findingDiff < 0
      });
    }

    // Comparison between latest two
    var comparison = null;
    if (sorted.length >= 2) {
      comparison = {
        scan1: sorted[sorted.length - 2],
        scan2: sorted[sorted.length - 1]
      };
    }

    return {
      trends: trends,
      scoreHistory: scoreHistory,
      findingsHistory: findingsHistory,
      comparison: comparison,
      totalScans: sorted.length
    };
  }

  /**
   * Render trend analysis as HTML.
   * @param {Object} trendData - Result from compute()
   * @returns {string} HTML string
   */
  function renderHtml(trendData) {
    if (!trendData || trendData.totalScans === 0) {
      return '<div class="no-data">No scan history available for trend analysis. Run multiple scans to see trends.</div>';
    }

    var html = '<div class="trend-container">';

    // Summary
    html += '<div class="trend-summary">';
    html += '  <span class="trend-summary-label">Scans Analyzed</span>';
    html += '  <span class="trend-summary-value">' + trendData.totalScans + '</span>';
    html += '</div>';

    // Trend indicators
    if (trendData.trends.length > 0) {
      html += '<div class="trend-indicators">';
      for (var t = 0; t < trendData.trends.length; t++) {
        var tr = trendData.trends[t];
        var arrow = tr.direction === 'up' ? '▲' : tr.direction === 'down' ? '▼' : '◆';
        var color = tr.improved ? 'var(--green, #22c55e)' : 'var(--accent, #ef4444)';
        html += '<div class="trend-card">';
        html += '  <div class="trend-card-header">' + esc(tr.metric) + '</div>';
        html += '  <div class="trend-card-value" style="color:' + color + '">';
        html += '    <span class="trend-arrow">' + arrow + '</span>';
        html += '    <span>' + tr.current + '</span>';
        html += '    <span class="trend-diff">(' + (tr.diff > 0 ? '+' : '') + tr.diff + ')</span>';
        html += '  </div>';
        html += '  <div class="trend-card-compare">from ' + tr.previous + '</div>';
        html += '</div>';
      }
      html += '</div>';
    }

    // Score history as simple bars
    if (trendData.scoreHistory.length > 1) {
      html += '<div class="trend-section">';
      html += '  <h4>Score History</h4>';
      html += '  <div class="trend-bars">';
      var maxScore = 100;
      for (var s = 0; s < trendData.scoreHistory.length; s++) {
        var sh = trendData.scoreHistory[s];
        var pct = (sh.score / maxScore) * 100;
        var barColor = sh.score >= 80 ? '#22c55e' : sh.score >= 55 ? '#eab308' : '#ef4444';
        html += '<div class="trend-bar-col">';
        html += '  <div class="trend-bar" style="height:' + pct + '%;background:' + barColor + '" title="' + sh.score + '/100"></div>';
        html += '  <div class="trend-bar-label">' + formatShortDate(sh.date) + '</div>';
        html += '</div>';
      }
      html += '  </div>';
      html += '</div>';
    }

    // Findings history
    if (trendData.findingsHistory.length > 1) {
      html += '<div class="trend-section">';
      html += '  <h4>Findings Over Time</h4>';
      html += '  <div class="trend-findings-table">';
      html += '    <table class="ent-table">';
      html += '      <thead><tr><th>Date</th><th>Issues</th><th>Info</th><th>Secure</th><th>Total</th></tr></thead>';
      html += '      <tbody>';
      for (var f = trendData.findingsHistory.length - 1; f >= 0; f--) {
        var fh = trendData.findingsHistory[f];
        html += '      <tr>';
        html += '        <td>' + formatShortDate(fh.date) + '</td>';
        html += '        <td class="risk-high">' + fh.issues + '</td>';
        html += '        <td>' + fh.info + '</td>';
        html += '        <td class="risk-secure">' + fh.secure + '</td>';
        html += '        <td>' + fh.total + '</td>';
        html += '      </tr>';
      }
      html += '      </tbody>';
      html += '    </table>';
      html += '  </div>';
      html += '</div>';
    }

    // Latest comparison
    if (trendData.comparison) {
      var c = trendData.comparison;
      html += '<div class="trend-section">';
      html += '  <h4>Latest Comparison</h4>';
      html += '  <div class="trend-compare-grid">';
      html += '    <div class="trend-compare-card">';
      html += '      <div class="trend-compare-label">Previous</div>';
      html += '      <div class="trend-compare-value">' + (c.scan1.score || '?') + '</div>';
      html += '      <div class="trend-compare-meta">' + formatShortDate(c.scan1.timestamp) + '</div>';
      html += '    </div>';
      html += '    <div class="trend-compare-arrow">→</div>';
      html += '    <div class="trend-compare-card current">';
      html += '      <div class="trend-compare-label">Current</div>';
      html += '      <div class="trend-compare-value">' + (c.scan2.score || '?') + '</div>';
      html += '      <div class="trend-compare-meta">' + formatShortDate(c.scan2.timestamp) + '</div>';
      html += '    </div>';
      html += '  </div>';
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  function esc(str) {
    if (str == null) return '';
    var d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function formatShortDate(iso) {
    if (!iso) return '';
    try {
      var d = new Date(iso);
      return d.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch (_) { return iso; }
  }

  return {
    compute: compute,
    renderHtml: renderHtml
  };
})();
