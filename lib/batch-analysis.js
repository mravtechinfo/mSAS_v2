/**
 * mSAS v2 — Batch Analysis Engine
 * 
 * Process multiple APK/IPA files sequentially with queue management,
 * aggregate stats, and cross-version comparison.
 * Part of Phase 8: UX Polish (UX-2).
 */

var MSAS = MSAS || {};

MSAS.BatchAnalysis = (function() {
  'use strict';

  var queue = [];
  var results = [];
  var isProcessing = false;
  var shouldStop = false;
  var currentIndex = -1;
  var callbacks = {};

  // ── Queue Management ───────────────────────────────────────

  /**
   * Add files to the analysis queue.
   * @param {File[]} files - Array of File objects
   * @returns {number} Queue length
   */
  function addToQueue(files) {
    if (!files || !files.length) return queue.length;
    
    for (var i = 0; i < files.length; i++) {
      var file = files[i];
      // Avoid duplicates by name + size
      var isDuplicate = queue.some(function(q) {
        return q.file.name === file.name && q.file.size === file.size;
      });
      if (!isDuplicate) {
        queue.push({
          file: file,
          status: 'pending', // pending | analyzing | done | error
          result: null,
          error: null,
          progress: 0,
          progressText: ''
        });
      }
    }
    
    trigger('queueChanged', { queue: queue.slice(), total: queue.length });
    return queue.length;
  }

  /**
   * Remove a file from the queue by index.
   */
  function removeFromQueue(index) {
    if (index >= 0 && index < queue.length) {
      if (queue[index].status === 'analyzing') return false; // Can't remove while analyzing
      queue.splice(index, 1);
      if (index < currentIndex) currentIndex--;
      trigger('queueChanged', { queue: queue.slice(), total: queue.length });
      return true;
    }
    return false;
  }

  /**
   * Clear the queue (except any currently analyzing file).
   */
  function clearQueue() {
    queue = queue.filter(function(q) { return q.status === 'analyzing'; });
    trigger('queueChanged', { queue: queue.slice(), total: queue.length });
  }

  /**
   * Get the current queue.
   */
  function getQueue() {
    return queue.slice();
  }

  /**
   * Get completed results.
   */
  function getResults() {
    return results.slice();
  }

  // ── Processing ─────────────────────────────────────────────

  /**
   * Start processing the queue.
   * @param {Function} analyzeFn - Async function(file) => result
   * @returns {Promise<Array>} All results when done
   */
  async function startProcessing(analyzeFn) {
    if (isProcessing) return;
    if (queue.length === 0) return;
    if (typeof analyzeFn !== 'function') return;

    isProcessing = true;
    var pending = queue.filter(function(q) { return q.status === 'pending'; });
    
    if (pending.length === 0) {
      isProcessing = false;
      return results.slice();
    }

    trigger('batchStarted', { total: pending.length });

    for (var i = 0; i < queue.length; i++) {
      if (shouldStop) break;
      var item = queue[i];
      if (item.status !== 'pending') continue;

      currentIndex = i;
      item.status = 'analyzing';
      item.progress = 0;
      trigger('fileStarted', { index: i, file: item.file.name, total: queue.length });

      try {
        item.result = await analyzeFn(item.file);
        item.status = 'done';
        item.progress = 100;
        results.push({
          file: item.file,
          result: item.result,
          index: i
        });
        trigger('fileDone', { index: i, file: item.file.name, result: item.result });
        
        // Save to scan history if available
        if (window.MSAS && MSAS.ScanHistory) {
          var meta = {
            appName: item.result.appInfo?.appLabel || item.result.appInfo?.packageName || item.file.name,
            auditorType: item.file.name.match(/\.ipa$/i) ? 'IPA' : 'APK',
            fileSize: item.file.size,
            fileName: item.file.name
          };
          MSAS.ScanHistory.saveScan(item.result, meta).catch(function() {});
        }
      } catch (e) {
        item.status = 'error';
        item.error = e.message || 'Unknown error';
        trigger('fileError', { index: i, file: item.file.name, error: item.error });
      }

      trigger('progress', {
        completed: i + 1,
        total: queue.length,
        percent: Math.round(((i + 1) / queue.length) * 100)
      });
    }

    var wasStopped = shouldStop;
    isProcessing = false;
    shouldStop = false;
    currentIndex = -1;
    trigger('batchComplete', { results: results.slice(), total: results.length, stopped: wasStopped });
    
    return results.slice();
  }

  /**
   * Update progress for the currently processing file.
   */
  function updateProgress(index, percent, text) {
    if (index >= 0 && index < queue.length) {
      queue[index].progress = percent || 0;
      queue[index].progressText = text || '';
      trigger('fileProgress', { index: index, percent: percent, text: text });
    }
  }

  /**
   * Check if batch is currently processing.
   */
  function stopProcessing() {
    if (!isProcessing) return;
    shouldStop = true;
  }

  function isBusy() {
    return isProcessing;
  }

  /**
   * Get aggregate stats across all completed results.
   * @returns {Object} { totalFiles, totalFindings, bySeverity, avgScore, bestScore, worstScore }
   */
  function getAggregateStats() {
    if (results.length === 0) {
      return { totalFiles: 0, totalFindings: 0, bySeverity: {}, avgScore: 0, bestScore: 0, worstScore: 100 };
    }

    var totalFindings = 0;
    var bySeverity = { issue: 0, info: 0, secure: 0 };
    var totalScore = 0;
    var bestScore = 0;
    var worstScore = 100;

    for (var r = 0; r < results.length; r++) {
      var res = results[r].result;
      var summary = res.summary || {};
      bySeverity.issue += summary.issue || 0;
      bySeverity.info += summary.info || 0;
      bySeverity.secure += summary.secure || 0;
      totalFindings += (summary.issue || 0) + (summary.info || 0) + (summary.secure || 0);
      
      var score = res.securityScore || 0;
      totalScore += score;
      if (score > bestScore) bestScore = score;
      if (score < worstScore) worstScore = score;
    }

    return {
      totalFiles: results.length,
      totalFindings: totalFindings,
      bySeverity: bySeverity,
      avgScore: Math.round(totalScore / results.length),
      bestScore: bestScore,
      worstScore: worstScore
    };
  }

  // ── Events ─────────────────────────────────────────────────

  function on(event, fn) {
    if (!callbacks[event]) callbacks[event] = [];
    callbacks[event].push(fn);
    return function() { off(event, fn); };
  }

  function off(event, fn) {
    if (!callbacks[event]) return;
    callbacks[event] = callbacks[event].filter(function(f) { return f !== fn; });
  }

  function trigger(event, data) {
    if (!callbacks[event]) return;
    for (var i = 0; i < callbacks[event].length; i++) {
      try { callbacks[event][i](data); } catch (e) { console.warn('[Batch] event handler error:', e); }
    }
  }

  // ── UI Rendering ───────────────────────────────────────────

  /**
   * Render the batch queue as HTML.
   */
  function renderQueueHtml() {
    if (queue.length === 0) {
      return '<div class="batch-empty">No files in queue. Select multiple APK/IPA files to begin batch analysis.</div>';
    }

    var html = '<div class="batch-queue">';
    for (var i = 0; i < queue.length; i++) {
      var item = queue[i];
      var statusIcon = item.status === 'done' ? '✅' : item.status === 'error' ? '❌' : item.status === 'analyzing' ? '⏳' : '⏸️';
      var statusClass = item.status === 'done' ? 'done' : item.status === 'error' ? 'error' : item.status === 'analyzing' ? 'active' : '';
      var score = item.result ? (item.result.securityScore || '?') : '';
      
      html += '<div class="batch-item ' + statusClass + '" data-index="' + i + '">';
      html += '  <span class="batch-item-icon">' + statusIcon + '</span>';
      html += '  <div class="batch-item-info">';
      html += '    <span class="batch-item-name">' + esc(item.file.name) + '</span>';
      html += '    <span class="batch-item-meta">' + fmtSize(item.file.size) + '</span>';
      if (item.status === 'analyzing' && item.progressText) {
        html += '    <span class="batch-item-progress-text">' + esc(item.progressText) + '</span>';
      }
      if (item.status === 'error') {
        html += '    <span class="batch-item-error">' + esc(item.error || 'Analysis failed') + '</span>';
      }
      html += '  </div>';
      if (score !== '') {
        html += '  <span class="batch-item-score">' + score + '</span>';
      }
      if (item.status !== 'analyzing' && !isProcessing) {
        html += '  <button class="batch-item-remove" data-index="' + i + '" title="Remove from queue">✕</button>';
      }
      if (item.status === 'analyzing') {
        html += '  <div class="batch-item-bar"><div class="batch-item-bar-fill" style="width:' + (item.progress || 0) + '%"></div></div>';
      }
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  /**
   * Render aggregate comparison of all batch results.
   */
  function renderAggregateHtml() {
    var stats = getAggregateStats();
    if (stats.totalFiles === 0) {
      return '<div class="no-data">No completed results yet.</div>';
    }

    var html = '<div class="batch-aggregate">';
    html += '<h4>Batch Summary (' + stats.totalFiles + ' files)</h4>';
    
    // Score cards
    html += '<div class="batch-aggregate-grid">';
    html += '  <div class="batch-stat-card"><div class="batch-stat-value">' + stats.totalFiles + '</div><div class="batch-stat-label">Files</div></div>';
    html += '  <div class="batch-stat-card"><div class="batch-stat-value good">' + stats.avgScore + '</div><div class="batch-stat-label">Avg Score</div></div>';
    html += '  <div class="batch-stat-card"><div class="batch-stat-value accent">' + stats.totalFindings + '</div><div class="batch-stat-label">Total Findings</div></div>';
    html += '  <div class="batch-stat-card"><div class="batch-stat-value blue">' + stats.bestScore + '</div><div class="batch-stat-label">Best</div></div>';
    html += '  <div class="batch-stat-card"><div class="batch-stat-value orange">' + stats.worstScore + '</div><div class="batch-stat-label">Worst</div></div>';
    html += '</div>';

    // Severity across all files
    html += '<div class="batch-aggregate-severity">';
    var sevs = [
      { key: 'issue', label: 'Issues', color: '#ef4444' },
      { key: 'info', label: 'Info', color: '#3b82f6' },
      { key: 'secure', label: 'Secure', color: '#22c55e' }
    ];
    var maxCount = Math.max(1, stats.bySeverity.issue || 0, stats.bySeverity.info || 0, stats.bySeverity.secure || 0);
    for (var s = 0; s < sevs.length; s++) {
      var sv = sevs[s];
      var count = stats.bySeverity[sv.key] || 0;
      var pct = (count / maxCount) * 100;
      html += '<div class="batch-sev-row">';
      html += '  <span class="batch-sev-label">' + sv.label + '</span>';
      html += '  <div class="batch-sev-track"><div class="batch-sev-fill" style="width:' + pct + '%;background:' + sv.color + '"></div></div>';
      html += '  <span class="batch-sev-count">' + count + '</span>';
      html += '</div>';
    }
    html += '</div>';

    // File comparison table
    html += '<div class="batch-file-comparison">';
    html += '<h4>File Comparison</h4>';
    html += '<table class="ent-table">';
    html += '<thead><tr><th>File</th><th>Score</th><th>Issues</th><th>Info</th><th>Secure</th></tr></thead><tbody>';
    for (var r = 0; r < results.length; r++) {
      var res = results[r];
      var sum = res.result.summary || {};
      var scoreClass = (res.result.securityScore || 0) >= 80 ? 'good' : (res.result.securityScore || 0) >= 55 ? 'ok' : 'bad';
      html += '<tr>';
      html += '  <td class="mono">' + esc(res.file.name) + '</td>';
      html += '  <td class="' + scoreClass + '">' + (res.result.securityScore || 0) + '</td>';
      html += '  <td class="batch-risk-high">' + (sum.issue || 0) + '</td>';
      html += '  <td>' + (sum.info || 0) + '</td>';
      html += '  <td class="batch-risk-secure">' + (sum.secure || 0) + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table>';
    html += '</div>';

    html += '</div>';
    return html;
  }

  // ── Helpers ────────────────────────────────────────────────

  function esc(str) {
    if (str == null) return '';
    var d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function fmtSize(b) {
    if (b == null) return '?';
    var u = ['B','KB','MB','GB'];
    var i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return b.toFixed(b < 10 && i > 0 ? 2 : 1) + ' ' + u[i];
  }

  return {
    addToQueue: addToQueue,
    removeFromQueue: removeFromQueue,
    clearQueue: clearQueue,
    getQueue: getQueue,
    getResults: getResults,
    startProcessing: startProcessing,
    updateProgress: updateProgress,
    isBusy: isBusy,
    getAggregateStats: getAggregateStats,
    on: on,
    off: off,
    renderQueueHtml: renderQueueHtml,
    renderAggregateHtml: renderAggregateHtml
  };
})();
