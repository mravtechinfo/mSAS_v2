/**
 * mSAS v2 — Shared Format Utilities (BASE-1)
 *
 * Extracted common formatting functions used across APK, IPA, and ADB auditors.
 * Provides stable, tested utilities via MSAS.SharedFormat namespace.
 *
 * Usage:
 *   var formatted = MSAS.SharedFormat.formatBytes(2048); // "2.0 KB"
 *   var escaped  = MSAS.SharedFormat.escapeHtml('<script>'); // "&lt;script&gt;"
 */

var MSAS = MSAS || {};
MSAS.SharedFormat = (function() {
  'use strict';

  // ── Byte Formatting ───────────────────────────────────────────

  /**
   * Format bytes into a human-readable string.
   * @param {number} bytes
   * @returns {string} e.g., "1.5 MB"
   */
  function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes) || bytes < 0) return '0 B';
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
  }

  // ── HTML Escaping ─────────────────────────────────────────────

  /**
   * Safely escape HTML to prevent XSS.
   * @param {*} str
   * @returns {string}
   */
  function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // ── Date Formatting ───────────────────────────────────────────

  /**
   * Format a date to ISO string or relative time.
   * @param {Date|string} date
   * @param {boolean} [relative] - If true, show relative time ("2 min ago")
   * @returns {string}
   */
  function formatDate(date, relative) {
    if (!date) return '';
    var d = typeof date === 'string' ? new Date(date) : date;
    if (!(d instanceof Date) || isNaN(d.getTime())) return '';

    if (relative) {
      var diff = Date.now() - d.getTime();
      var seconds = Math.floor(diff / 1000);
      if (seconds < 5) return 'just now';
      if (seconds < 60) return seconds + 's ago';
      var minutes = Math.floor(seconds / 60);
      if (minutes < 60) return minutes + 'm ago';
      var hours = Math.floor(minutes / 60);
      if (hours < 24) return hours + 'h ago';
      var days = Math.floor(hours / 24);
      if (days < 30) return days + 'd ago';
      var months = Math.floor(days / 30);
      return months + 'mo ago';
    }
    return d.toISOString();
  }

  // ── String Truncation ─────────────────────────────────────────

  /**
   * Truncate a string in the middle for display in narrow columns.
   * e.g., truncateMiddle("abcdefghijklmnop", 10) → "abc...nop"
   * @param {string} str
   * @param {number} maxLen
   * @returns {string}
   */
  function truncateMiddle(str, maxLen) {
    if (!str || str.length <= maxLen) return str || '';
    var half = Math.floor((maxLen - 3) / 2);
    return str.slice(0, half) + '...' + str.slice(str.length - half);
  }

  // ── Duration Formatting ───────────────────────────────────────

  /**
   * Format a duration in milliseconds to a human-readable string.
   * @param {number} ms - Duration in milliseconds
   * @returns {string} e.g., "2m 34s"
   */
  function formatDuration(ms) {
    if (ms == null || isNaN(ms) || ms < 0) return '0s';
    var totalSeconds = Math.floor(ms / 1000);
    if (totalSeconds < 60) return totalSeconds + 's';
    var minutes = Math.floor(totalSeconds / 60);
    var seconds = totalSeconds % 60;
    if (minutes < 60) return minutes + 'm ' + seconds + 's';
    var hours = Math.floor(minutes / 60);
    minutes = minutes % 60;
    return hours + 'h ' + minutes + 'm';
  }

  // ── Percentage Formatting ─────────────────────────────────────

  /**
   * Format a decimal as a percentage string.
   * @param {number} value - e.g., 0.756
   * @param {number} [decimals=1]
   * @returns {string} e.g., "75.6%"
   */
  function formatPercent(value, decimals) {
    if (value == null || isNaN(value)) return '0%';
    var d = decimals != null ? decimals : 1;
    return (value * 100).toFixed(d) + '%';
  }

  // ── Number Formatting ─────────────────────────────────────────

  /**
   * Format a number with commas.
   * @param {number} n
   * @returns {string} e.g., "1,234,567"
   */
  function formatNumber(n) {
    if (n == null || isNaN(n)) return '0';
    return Number(n).toLocaleString('en-US');
  }

  // ── SDK Version Mapping ───────────────────────────────────────

  var SDK_MAP = {
    14: '4.0',   15: '4.0.3', 16: '4.1',   17: '4.2',
    18: '4.3',   19: '4.4',   21: '5.0',   22: '5.1',
    23: '6.0',   24: '7.0',   25: '7.1',   26: '8.0',
    27: '8.1',   28: '9',     29: '10',    30: '11',
    31: '12',    32: '12L',   33: '13',    34: '14',   35: '15'
  };

  /**
   * Convert Android SDK API level to version string.
   * @param {number|string} sdk - SDK API level
   * @returns {string} e.g., 33 → "13"
   */
  function sdkToVer(sdk) {
    return SDK_MAP[sdk] || String(sdk);
  }

  // ── Public API ────────────────────────────────────────────────

  return {
    formatBytes:    formatBytes,
    escapeHtml:     escapeHtml,
    formatDate:     formatDate,
    truncateMiddle: truncateMiddle,
    formatDuration: formatDuration,
    formatPercent:  formatPercent,
    formatNumber:   formatNumber,
    sdkToVer:       sdkToVer
  };
})();
