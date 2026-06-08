/**
 * mSAS v2 — Evidence Attachment Module
 * 
 * Attach screenshots, log snippets, and code evidence to findings.
 * Part of Phase 7: Reporting Suite (RPT-7).
 */

var MSAS = MSAS || {};

MSAS.Evidence = (function() {
  'use strict';

  var evidenceStore = {}; // findingId -> [evidence items]

  /**
   * Create a new evidence attachment.
   * @param {Object} opts - { id, findingId, type, label, content, dataUrl }
   * @returns {Object} evidence record
   */
  function createEvidence(opts) {
    var evidence = {
      id: opts.id || 'ev-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6),
      findingId: opts.findingId || '',
      type: opts.type || 'note',       // 'note' | 'snippet' | 'screenshot' | 'log'
      label: opts.label || 'Evidence',
      content: opts.content || '',
      dataUrl: opts.dataUrl || '',
      timestamp: new Date().toISOString(),
      meta: opts.meta || {}
    };

    if (!evidenceStore[evidence.findingId]) {
      evidenceStore[evidence.findingId] = [];
    }
    evidenceStore[evidence.findingId].push(evidence);
    return evidence;
  }

  /**
   * Get all evidence for a finding.
   */
  function getEvidence(findingId) {
    return evidenceStore[findingId] || [];
  }

  /**
   * Get all evidence across all findings.
   */
  function getAllEvidence() {
    var all = [];
    for (var key in evidenceStore) {
      all = all.concat(evidenceStore[key]);
    }
    return all;
  }

  /**
   * Remove evidence by ID.
   */
  function removeEvidence(evId) {
    for (var key in evidenceStore) {
      var arr = evidenceStore[key];
      for (var i = 0; i < arr.length; i++) {
        if (arr[i].id === evId) {
          arr.splice(i, 1);
          if (arr.length === 0) delete evidenceStore[key];
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Clear all evidence for a finding.
   */
  function clearEvidence(findingId) {
    delete evidenceStore[findingId];
  }

  /**
   * Create evidence from a text snippet.
   */
  function fromSnippet(findingId, label, code) {
    return createEvidence({
      findingId: findingId,
      type: 'snippet',
      label: label || 'Code Snippet',
      content: code || '',
      meta: { lines: (code || '').split('\n').length }
    });
  }

  /**
   * Create evidence from a screenshot (data URL).
   */
  function fromScreenshot(findingId, label, dataUrl) {
    return createEvidence({
      findingId: findingId,
      type: 'screenshot',
      label: label || 'Screenshot',
      dataUrl: dataUrl || '',
      meta: { format: 'data-url' }
    });
  }

  /**
   * Create evidence from a log entry.
   */
  function fromLog(findingId, label, logContent) {
    return createEvidence({
      findingId: findingId,
      type: 'log',
      label: label || 'Log Snippet',
      content: logContent || '',
      meta: { lines: (logContent || '').split('\n').length }
    });
  }

  /**
   * Render evidence for a finding as HTML.
   */
  function renderEvidenceHtml(findingId) {
    var items = getEvidence(findingId);
    if (items.length === 0) return '';

    var html = '<div class="evidence-section">';
    html += '<div class="evidence-header">Evidence (' + items.length + ')</div>';
    html += '<div class="evidence-list">';

    for (var i = 0; i < items.length; i++) {
      var ev = items[i];
      var typeIcon = { note: '📝', snippet: '💻', screenshot: '📸', log: '📋' };
      html += '<div class="evidence-item" data-evidence-id="' + ev.id + '">';
      html += '  <div class="evidence-item-header">';
      html += '    <span class="evidence-type-icon">' + (typeIcon[ev.type] || '📎') + '</span>';
      html += '    <span class="evidence-label">' + esc(ev.label) + '</span>';
      html += '    <span class="evidence-timestamp">' + formatTime(ev.timestamp) + '</span>';
      html += '    <button class="evidence-remove-btn" data-evidence-id="' + ev.id + '" title="Remove evidence">✕</button>';
      html += '  </div>';

      if (ev.type === 'screenshot' && ev.dataUrl) {
        html += '  <div class="evidence-screenshot">';
        html += '    <img src="' + ev.dataUrl + '" alt="' + esc(ev.label) + '" loading="lazy" onclick="window.open(this.src)">';
        html += '  </div>';
      } else if (ev.content) {
        html += '  <pre class="evidence-content mono">' + esc(ev.content.slice(0, 2000)) + '</pre>';
        if (ev.content.length > 2000) {
          html += '  <div class="evidence-truncated">… truncated (' + ev.content.length + ' chars)</div>';
        }
      }

      html += '</div>';
    }

    html += '</div></div>';
    return html;
  }

  /**
   * Render the evidence attachment form for a finding.
   */
  function renderAttachmentForm(findingId) {
    return '<div class="evidence-attach-form" data-finding-id="' + findingId + '">' +
      '<div class="evidence-attach-row">' +
      '  <input type="text" class="evidence-label-input" placeholder="Label (e.g., Code snippet, Screenshot)" maxlength="100">' +
      '</div>' +
      '<div class="evidence-attach-row">' +
      '  <textarea class="evidence-content-input" placeholder="Paste code snippet, log, or notes here…" rows="3"></textarea>' +
      '</div>' +
      '<div class="evidence-attach-row">' +
      '  <button class="evidence-attach-btn evidence-attach-note" data-finding-id="' + findingId + '">📝 Attach Note</button>' +
      '  <button class="evidence-attach-btn evidence-attach-snippet" data-finding-id="' + findingId + '">💻 Attach Snippet</button>' +
      '  <button class="evidence-attach-btn evidence-attach-log" data-finding-id="' + findingId + '">📋 Attach Log</button>' +
      '</div>' +
      '</div>';
  }

  function esc(str) {
    if (str == null) return '';
    var d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function formatTime(iso) {
    if (!iso) return '';
    try {
      var d = new Date(iso);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch (_) { return iso; }
  }

  /**
   * Wire up evidence attachment UI events within a container.
   * Handles remove buttons and attach buttons (note, snippet, log).
   */
  function bindEvents(container) {
    if (!container) return;
    
    // Remove evidence buttons
    container.querySelectorAll('[data-evidence-id]').forEach(function(btn) {
      btn.addEventListener('click', function(e) {
        var id = btn.getAttribute('data-evidence-id');
        if (id && removeEvidence(id)) {
          var item = btn.closest('.evidence-item');
          if (item) item.remove();
        }
      });
    });

    // Attach note button
    container.querySelectorAll('.evidence-attach-note').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var findingId = btn.getAttribute('data-finding-id');
        if (!findingId) return;
        var form = btn.closest('.evidence-attach-form');
        if (!form) return;
        var labelInput = form.querySelector('.evidence-label-input');
        var contentInput = form.querySelector('.evidence-content-input');
        var label = (labelInput && labelInput.value.trim()) || 'Note';
        var content = (contentInput && contentInput.value.trim()) || '';
        if (!content) return;
        
        createEvidence({
          findingId: findingId,
          type: 'note',
          label: label,
          content: content
        });
        
        if (labelInput) labelInput.value = '';
        if (contentInput) contentInput.value = '';
        
        // Refresh evidence display
        var evidenceSection = form.closest('.finding-body') || form.closest('.evidence-section');
        if (evidenceSection) {
          var existingSection = evidenceSection.querySelector('.evidence-section');
          if (existingSection) {
            existingSection.outerHTML = renderEvidenceHtml(findingId);
          } else {
            // Insert new evidence section before the form
            var insertTarget = form.closest('.evidence-attach') || form.parentNode;
            insertTarget.insertAdjacentHTML('beforebegin', renderEvidenceHtml(findingId));
          }
          // Re-bind events
          bindEvents(evidenceSection);
        }
      });
    });

    // Attach snippet button
    container.querySelectorAll('.evidence-attach-snippet').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var findingId = btn.getAttribute('data-finding-id');
        if (!findingId) return;
        var form = btn.closest('.evidence-attach-form');
        if (!form) return;
        var labelInput = form.querySelector('.evidence-label-input');
        var contentInput = form.querySelector('.evidence-content-input');
        var label = (labelInput && labelInput.value.trim()) || 'Code Snippet';
        var content = (contentInput && contentInput.value.trim()) || '';
        if (!content) return;
        
        fromSnippet(findingId, label, content);
        
        if (labelInput) labelInput.value = '';
        if (contentInput) contentInput.value = '';
        
        var evidenceSection = form.closest('.finding-body') || form.closest('.evidence-section');
        if (evidenceSection) {
          var existingSection = evidenceSection.querySelector('.evidence-section');
          if (existingSection) {
            existingSection.outerHTML = renderEvidenceHtml(findingId);
          } else {
            var insertTarget = form.closest('.evidence-attach') || form.parentNode;
            insertTarget.insertAdjacentHTML('beforebegin', renderEvidenceHtml(findingId));
          }
          bindEvents(evidenceSection);
        }
      });
    });

    // Attach log button
    container.querySelectorAll('.evidence-attach-log').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var findingId = btn.getAttribute('data-finding-id');
        if (!findingId) return;
        var form = btn.closest('.evidence-attach-form');
        if (!form) return;
        var labelInput = form.querySelector('.evidence-label-input');
        var contentInput = form.querySelector('.evidence-content-input');
        var label = (labelInput && labelInput.value.trim()) || 'Log Snippet';
        var content = (contentInput && contentInput.value.trim()) || '';
        if (!content) return;
        
        fromLog(findingId, label, content);
        
        if (labelInput) labelInput.value = '';
        if (contentInput) contentInput.value = '';
        
        var evidenceSection = form.closest('.finding-body') || form.closest('.evidence-section');
        if (evidenceSection) {
          var existingSection = evidenceSection.querySelector('.evidence-section');
          if (existingSection) {
            existingSection.outerHTML = renderEvidenceHtml(findingId);
          } else {
            var insertTarget = form.closest('.evidence-attach') || form.parentNode;
            insertTarget.insertAdjacentHTML('beforebegin', renderEvidenceHtml(findingId));
          }
          bindEvents(evidenceSection);
        }
      });
    });
  }

  return {
    createEvidence: createEvidence,
    getEvidence: getEvidence,
    getAllEvidence: getAllEvidence,
    removeEvidence: removeEvidence,
    clearEvidence: clearEvidence,
    fromSnippet: fromSnippet,
    fromScreenshot: fromScreenshot,
    fromLog: fromLog,
    renderEvidenceHtml: renderEvidenceHtml,
    renderAttachmentForm: renderAttachmentForm,
    bindEvents: bindEvents
  };
})();
