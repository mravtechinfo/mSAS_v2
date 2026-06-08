/**
 * mSAS v2 — Scan History Storage
 * 
 * IndexedDB-backed scan history with browse, search, compare, naming, tags.
 * Part of Phase 8: UX Polish (UX-6).
 */

var MSAS = MSAS || {};

MSAS.ScanHistory = (function() {
  'use strict';

  var DB_NAME = 'mSAS_ScanHistory';
  var DB_VERSION = 1;
  var STORE_NAME = 'scans';
  var db = null;

  /**
   * Open (or create) the IndexedDB database.
   * @returns {Promise<IDBDatabase>}
   */
  function openDB() {
    return new Promise(function(resolve, reject) {
      if (db) return resolve(db);

      if (!window.indexedDB) {
        reject(new Error('IndexedDB not supported'));
        return;
      }

      var request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = function(e) {
        var database = e.target.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) {
          var store = database.createObjectStore(STORE_NAME, { keyPath: 'id', autoIncrement: true });
          store.createIndex('timestamp', 'timestamp', { unique: false });
          store.createIndex('appName', 'appName', { unique: false });
          store.createIndex('auditorType', 'auditorType', { unique: false });
          store.createIndex('score', 'score', { unique: false });
          store.createIndex('tags', 'tags', { unique: false, multiEntry: true });
        }
      };

      request.onsuccess = function(e) {
        db = e.target.result;
        resolve(db);
      };

      request.onerror = function(e) {
        reject(new Error('Failed to open IndexedDB: ' + e.target.error));
      };
    });
  }

  /**
   * Save a scan result to history.
   * @param {Object} result - Analysis result
   * @param {Object} meta - { appName, auditorType, fileSize, fileName }
   * @param {Object} options - { name, tags, notes }
   * @returns {Promise<number>} The scan ID
   */
  function saveScan(result, meta, options) {
    return openDB().then(function(database) {
      return new Promise(function(resolve, reject) {
        var summary = result.summary || {};
        var severityDist = {};
        if (result.groupedFindings) {
          severityDist = {
            issue: (result.groupedFindings.issue || []).length,
            info: (result.groupedFindings.info || []).length,
            secure: (result.groupedFindings.secure || []).length
          };
        }

        var record = {
          timestamp: new Date().toISOString(),
          appName: meta?.appName || result.appInfo?.appLabel || result.appInfo?.packageName || 'Unknown',
          packageName: result.appInfo?.packageName || '',
          auditorType: meta?.auditorType || 'APK',
          versionName: result.appInfo?.versionName || '',
          versionCode: result.appInfo?.versionCode || '',
          fileSize: meta?.fileSize || 0,
          fileName: meta?.fileName || '',
          score: result.securityScore || 0,
          totalFindings: summary.issue || 0,
          severityDist: severityDist,
          name: options?.name || '',
          tags: options?.tags || [],
          notes: options?.notes || ''
        };

        var tx = database.transaction([STORE_NAME], 'readwrite');
        var store = tx.objectStore(STORE_NAME);
        var request = store.add(record);

        request.onsuccess = function() {
          resolve(request.result);
        };
        request.onerror = function() {
          reject(new Error('Failed to save scan: ' + request.error));
        };
      });
    });
  }

  /**
   * Load all scan history entries.
   * @returns {Promise<Array>} List of scan records
   */
  function listScans() {
    return openDB().then(function(database) {
      return new Promise(function(resolve, reject) {
        var tx = database.transaction([STORE_NAME], 'readonly');
        var store = tx.objectStore(STORE_NAME);
        var index = store.index('timestamp');
        var request = index.openCursor(null, 'prev');
        var scans = [];

        request.onsuccess = function(e) {
          var cursor = e.target.result;
          if (cursor) {
            scans.push(cursor.value);
            cursor.continue();
          } else {
            resolve(scans);
          }
        };
        request.onerror = function() {
          reject(new Error('Failed to list scans'));
        };
      });
    });
  }

  /**
   * Get a single scan by ID.
   * @param {number} id - Scan ID
   * @returns {Promise<Object|null>}
   */
  function getScan(id) {
    return openDB().then(function(database) {
      return new Promise(function(resolve, reject) {
        var tx = database.transaction([STORE_NAME], 'readonly');
        var store = tx.objectStore(STORE_NAME);
        var request = store.get(id);

        request.onsuccess = function() {
          resolve(request.result || null);
        };
        request.onerror = function() {
          reject(new Error('Failed to get scan'));
        };
      });
    });
  }

  /**
   * Delete a scan by ID.
   * @param {number} id - Scan ID
   * @returns {Promise<void>}
   */
  function deleteScan(id) {
    return openDB().then(function(database) {
      return new Promise(function(resolve, reject) {
        var tx = database.transaction([STORE_NAME], 'readwrite');
        var store = tx.objectStore(STORE_NAME);
        var request = store.delete(id);

        request.onsuccess = function() {
          resolve();
        };
        request.onerror = function() {
          reject(new Error('Failed to delete scan'));
        };
      });
    });
  }

  /**
   * Search scans by app name, tags, or notes.
   * @param {string} query - Search text
   * @returns {Promise<Array>}
   */
  function searchScans(query) {
    var q = (query || '').toLowerCase().trim();
    if (!q) return listScans();

    return listScans().then(function(scans) {
      return scans.filter(function(s) {
        return (s.appName && s.appName.toLowerCase().indexOf(q) >= 0) ||
               (s.packageName && s.packageName.toLowerCase().indexOf(q) >= 0) ||
               (s.name && s.name.toLowerCase().indexOf(q) >= 0) ||
               (s.notes && s.notes.toLowerCase().indexOf(q) >= 0) ||
               (s.tags && s.tags.some(function(t) { return t.toLowerCase().indexOf(q) >= 0; }));
      });
    });
  }

  /**
   * Compare two scans side-by-side.
   * @param {number} id1 - First scan ID
   * @param {number} id2 - Second scan ID
   * @returns {Promise<Object>} Comparison data
   */
  function compareScans(id1, id2) {
    return Promise.all([getScan(id1), getScan(id2)]).then(function(results) {
      var a = results[0];
      var b = results[1];
      if (!a || !b) throw new Error('One or both scans not found');

      return {
        scan1: a,
        scan2: b,
        scoreDiff: (a.score || 0) - (b.score || 0),
        findingsDiff: (a.severityDist?.issue || 0) - (b.severityDist?.issue || 0)
      };
    });
  }

  /**
   * Update scan metadata (name, tags, notes).
   * @param {number} id - Scan ID
   * @param {Object} updates - { name, tags, notes }
   * @returns {Promise<void>}
   */
  function updateScan(id, updates) {
    return openDB().then(function(database) {
      return new Promise(function(resolve, reject) {
        var tx = database.transaction([STORE_NAME], 'readwrite');
        var store = tx.objectStore(STORE_NAME);
        var getReq = store.get(id);

        getReq.onsuccess = function() {
          var record = getReq.result;
          if (!record) {
            reject(new Error('Scan not found'));
            return;
          }
          if (updates.name !== undefined) record.name = updates.name;
          if (updates.tags !== undefined) record.tags = updates.tags;
          if (updates.notes !== undefined) record.notes = updates.notes;

          var putReq = store.put(record);
          putReq.onsuccess = function() { resolve(); };
          putReq.onerror = function() { reject(new Error('Failed to update scan')); };
        };
        getReq.onerror = function() {
          reject(new Error('Failed to get scan for update'));
        };
      });
    });
  }

  /**
   * Render scan history as HTML.
   * @param {Array} scans - List from listScans() or searchScans()
   * @returns {string} HTML string
   */
  function renderHistoryHtml(scans) {
    if (!scans || scans.length === 0) {
      return '<div class="no-data">No scan history yet. Run an analysis and it will appear here.</div>';
    }

    var html = '<div class="scan-history-list">';
    for (var i = 0; i < scans.length; i++) {
      var s = scans[i];
      var scoreClass = s.score >= 80 ? 'good' : s.score >= 55 ? 'ok' : 'bad';
      html += '<article class="scan-history-card" data-scan-id="' + s.id + '">';
      html += '  <div class="scan-history-score ' + scoreClass + '">' + (s.score || '?') + '</div>';
      html += '  <div class="scan-history-info">';
      html += '    <div class="scan-history-name">' + esc(s.name || s.appName || 'Unknown') + '</div>';
      html += '    <div class="scan-history-meta">';
      html += '      <span class="scan-history-auditor">' + esc(s.auditorType || 'APK') + '</span>';
      html += '      <span class="scan-history-date">' + formatDate(s.timestamp) + '</span>';
      if (s.packageName) html += '      <span class="scan-history-pkg mono">' + esc(s.packageName) + '</span>';
      html += '    </div>';
      if (s.severityDist) {
        html += '    <div class="scan-history-findings">';
        html += '      <span class="scan-finding-badge issue">' + (s.severityDist.issue || 0) + ' issues</span>';
        html += '      <span class="scan-finding-badge info">' + (s.severityDist.info || 0) + ' info</span>';
        html += '      <span class="scan-finding-badge secure">' + (s.severityDist.secure || 0) + ' secure</span>';
        html += '    </div>';
      }
      if (s.tags && s.tags.length > 0) {
        html += '    <div class="scan-history-tags">';
        for (var t = 0; t < s.tags.length; t++) {
          html += '  <span class="scan-tag">' + esc(s.tags[t]) + '</span>';
        }
        html += '    </div>';
      }
      html += '  </div>';
      html += '  <div class="scan-history-actions">';
      html += '    <button class="scan-action-btn" data-action="view" data-scan-id="' + s.id + '" title="View details">View</button>';
      html += '    <button class="scan-action-btn" data-action="delete" data-scan-id="' + s.id + '" title="Delete">🗑️</button>';
      html += '  </div>';
      html += '</article>';
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

  function formatDate(iso) {
    if (!iso) return '';
    try {
      var d = new Date(iso);
      var now = new Date();
      var diffMs = now - d;
      var diffDays = Math.floor(diffMs / 86400000);
      if (diffDays === 0) return 'Today ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      if (diffDays === 1) return 'Yesterday ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      if (diffDays < 7) return diffDays + ' days ago';
      return d.toLocaleDateString();
    } catch (_) {
      return iso;
    }
  }

  return {
    saveScan: saveScan,
    listScans: listScans,
    getScan: getScan,
    deleteScan: deleteScan,
    searchScans: searchScans,
    compareScans: compareScans,
    updateScan: updateScan,
    renderHistoryHtml: renderHistoryHtml
  };
})();
