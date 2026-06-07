/**
 * mSAS v2 — Shared Utilities
 * 
 * Common helpers used across APK, IPA, and ADB auditors.
 */

var MSAS = MSAS || {};
MSAS.Utils = (function() {
  'use strict';

  /**
   * Safely escapes HTML to prevent XSS in findings output
   */
  function escapeHtml(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }

  /**
   * Formats bytes into a human-readable string
   */
  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
  }

  /**
   * Formats a date to ISO string or relative time
   */
  function formatDate(date, relative) {
    if (!date) return '';
    var d = typeof date === 'string' ? new Date(date) : date;
    if (relative) {
      var diff = Date.now() - d.getTime();
      var mins = Math.floor(diff / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return mins + 'm ago';
      var hours = Math.floor(mins / 60);
      if (hours < 24) return hours + 'h ago';
      var days = Math.floor(hours / 24);
      return days + 'd ago';
    }
    return d.toISOString();
  }

  /**
   * Deep clone a plain object
   */
  function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
  }

  /**
   * Simple debounce
   */
  function debounce(fn, delay) {
    var timer = null;
    return function() {
      var args = arguments;
      var ctx = this;
      clearTimeout(timer);
      timer = setTimeout(function() {
        fn.apply(ctx, args);
      }, delay || 300);
    };
  }

  /**
   * Groups an array of results by a key field
   */
  function groupBy(arr, key) {
    var map = {};
    arr.forEach(function(item) {
      var val = item[key] || 'other';
      if (!map[val]) map[val] = [];
      map[val].push(item);
    });
    return map;
  }

  /**
   * Counts findings by severity
   */
  function countBySeverity(results) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    results.forEach(function(r) {
      if (counts[r.severity] !== undefined) counts[r.severity]++;
    });
    return counts;
  }

  /**
   * Parses an XML string to a DOM Document
   */
  function parseXml(xmlStr) {
    if (typeof xmlStr !== 'string') return null;
    try {
      var parser = new DOMParser();
      return parser.parseFromString(xmlStr, 'text/xml');
    } catch(e) {
      return null;
    }
  }

  /**
   * Generates a unique ID
   */
  function uid() {
    return 'msas-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 6);
  }

  /**
   * Finds which signatures exist in a string array (up to 50K limit)
   * Used by v2 scanners to detect library/API references in DEX strings
   * @param {string[]} strings - DEX string pool
   * @param {string[]} signatures - Patterns to search for
   * @returns {string[]} Matching signatures found
   */
  function findInStrings(strings, signatures) {
    var limit = Math.min(strings.length, 50000);
    var found = [];
    for (var i = 0; i < signatures.length; i++) {
      for (var j = 0; j < limit; j++) {
        if (strings[j].indexOf(signatures[i]) >= 0) {
          found.push(signatures[i]);
          break;
        }
      }
    }
    return found;
  }

  /**
   * Checks if any of the signatures exist in the string array
   * @param {string[]} strings - DEX string pool
   * @param {string[]} signatures - Patterns to search for
   * @returns {boolean}
   */
  function hasInStrings(strings, signatures) {
    return findInStrings(strings, signatures).length > 0;
  }

  return {
    escapeHtml:      escapeHtml,
    formatBytes:     formatBytes,
    formatDate:      formatDate,
    deepClone:       deepClone,
    debounce:        debounce,
    groupBy:         groupBy,
    countBySeverity: countBySeverity,
    parseXml:        parseXml,
    uid:             uid,
    findInStrings:   findInStrings,
    hasInStrings:    hasInStrings
  };
})();
