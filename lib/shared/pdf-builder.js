/**
 * mSAS v2 — Unified PDF Report Builder (BASE-4)
 *
 * Merges the common PDF rendering logic from APK Auditor, IPA Auditor, and ADB Auditor
 * into a single shared module with consistent mSAS v2 emerald branding.
 *
 * Features:
 *   - Emerald (#10B981) branded cover page, section headers, and footer
 *   - CVSS 3.1 severity coloring throughout findings
 *   - MASTG references on every finding card
 *   - Security score ring with grade label
 *   - Works with any auditor's results format (APK, IPA, or ADB)
 *
 * The existing auditor-specific PDF generators (apk-auditor/src/core/pdf.js,
 * ipa-auditor/src/core/pdf.js, adb-auditor/js/pdf.js) remain for backward
 * compatibility. New code should use MSAS.SharedPdf for unified reports.
 *
 * Usage:
 *   // Build a complete executive PDF
 *   var pdfBuilder = new MSAS.SharedPdf.PDFBuilder();
 *   var doc = pdfBuilder.build(results, { platform: 'apk', appName: 'MyApp' });
 *   doc.save('report.pdf');
 *
 *   // Or use the convenience function
 *   MSAS.SharedPdf.exportExecutiveReport(results, { platform: 'ipa' });
 */

var MSAS = MSAS || {};
MSAS.SharedPdf = (function() {
  'use strict';

  // ── Constants ──────────────────────────────────────────────

  var PAGE = { w: 595, h: 842, margin: 48 };
  var CONTENT = { x: PAGE.margin, w: PAGE.w - 2 * PAGE.margin };
  var MAX_Y = PAGE.h - PAGE.margin - 28;

  // Emerald (#10B981) themed color palette matching mSAS v2 design system
  var COLORS = {
    text:        [15, 20, 28],
    textMuted:   [95, 105, 120],
    textSubtle:  [155, 165, 180],
    border:      [222, 226, 232],
    accent:      [16, 185, 129],    // #10B981 emerald primary
    accentDark:  [4, 120, 87],      // #047857 emerald dark
    accentSub:   [167, 243, 208],   // #A7F3D0 emerald light/subtle
    critical:    [190, 18, 60],     // #BE123C
    high:        [180, 83, 9],      // #B45309
    medium:      [180, 115, 9],     // #B47309
    low:         [14, 124, 177],    // #0E7CB1
    info:        [95, 105, 120],    // #5F6978
    secure:      [16, 185, 129],    // Emerald for passed/secure
    cardBg:      [245, 247, 250],
    bgAlt:       [238, 241, 246],
    white:       [255, 255, 255]
  };

  var FONT_SIZES = {
    coverTitle: 30,
    coverSubtitle: 11,
    pageTitle: 22,
    sectionHeader: 14,
    subHeader: 10.5,
    body: 10,
    small: 9,
    tiny: 8,
    micro: 7
  };

  // ── Severity Helpers ───────────────────────────────────────

  /**
   * Map a severity string to a color array.
   * Supports both legacy (issue, secure, warning) and standard (critical, high) severities.
   */
  function severityColor(sev) {
    var s = (sev || '').toLowerCase();
    if (s === 'critical') return COLORS.critical;
    if (s === 'high' || s === 'issue') return COLORS.high;
    if (s === 'medium' || s === 'warning' || s === 'review') return COLORS.medium;
    if (s === 'low' || s === 'info') return COLORS.low;
    if (s === 'secure' || s === 'pass') return COLORS.secure;
    return COLORS.accent;
  }

  /**
   * Convert severity to a label for display.
   */
  function severityLabel(sev) {
    var s = (sev || '').toLowerCase();
    if (s === 'issue') return 'HIGH';
    if (s === 'warning' || s === 'review') return 'MEDIUM';
    return s.toUpperCase();
  }

  /**
   * Get score color based on security score.
   */
  function scoreColor(score) {
    if (score >= 85) return COLORS.secure;
    if (score >= 70) return COLORS.low;
    if (score >= 50) return COLORS.medium;
    if (score >= 30) return COLORS.high;
    return COLORS.critical;
  }

  /**
   * Get score grade label.
   */
  function scoreGrade(score) {
    if (score >= 85) return 'Excellent';
    if (score >= 70) return 'Good';
    if (score >= 50) return 'Fair';
    if (score >= 30) return 'Poor';
    return 'Critical';
  }

  // ── jsPDF Initialization ───────────────────────────────────

  function initJsPdf() {
    var jspdfNs = (typeof window !== 'undefined' ? window.jspdf : null)
                || (typeof globalThis !== 'undefined' ? globalThis.jspdf : null);
    if (!jspdfNs || !jspdfNs.jsPDF) {
      throw new Error('jsPDF library not loaded. Include lib/jspdf.umd.min.js');
    }
    return new jspdfNs.jsPDF({ unit: 'pt', format: 'a4', compress: true });
  }

  // ── PDF Builder Class ───────────────────────────────────────

  /**
   * Creates a new PDF builder instance.
   * @constructor
   */
  function PDFBuilder() {
    this.doc = null;
    this.y = PAGE.margin;
    this.pageNo = 1;
    this.results = null;
    this.options = {};
    this._platform = 'generic';
  }

  /**
   * Initialize the builder with results and options.
   * Called automatically by build().
   */
  PDFBuilder.prototype._init = function(results, opts) {
    this.doc = initJsPdf();
    this.y = PAGE.margin;
    this.pageNo = 1;
    this.results = results || {};
    this.options = opts || {};
    this._platform = (opts.platform || 'generic').toLowerCase();
  };

  // ── Font & Style Helpers ────────────────────────────────────

  PDFBuilder.prototype.setFont = function(family, style, size) {
    this.doc.setFont(family || 'helvetica', style || 'normal');
    if (size) this.doc.setFontSize(size);
  };

  PDFBuilder.prototype.setTColor = function(color) {
    this.doc.setTextColor(color[0], color[1], color[2]);
  };

  PDFBuilder.prototype.setFill = function(color) {
    this.doc.setFillColor(color[0], color[1], color[2]);
  };

  PDFBuilder.prototype.setDraw = function(color) {
    this.doc.setDrawColor(color[0], color[1], color[2]);
  };

  PDFBuilder.prototype.setLineW = function(w) {
    this.doc.setLineWidth(w || 0.5);
  };

  // ── Page Management ─────────────────────────────────────────

  PDFBuilder.prototype.ensure = function(h) {
    if (this.y + h > MAX_Y) this.addPage(false);
  };

  PDFBuilder.prototype.addPage = function(skipHeader) {
    this.doc.addPage();
    this.pageNo++;
    this.y = PAGE.margin;
    if (!skipHeader) this._drawPageHeader();
  };

  PDFBuilder.prototype._drawPageHeader = function() {
    var d = this.doc;
    var platformLabel = this._platformLabel();
    var appName = this._getAppName() || 'Report';

    this.setFont('helvetica', 'normal', FONT_SIZES.micro);
    this.setTColor(COLORS.textSubtle);
    d.text(platformLabel + ' / ' + appName, PAGE.margin, 28);
    d.text(String(this.pageNo), PAGE.w - PAGE.margin, 28, { align: 'right' });

    // Emerald accent line
    this.setDraw(COLORS.accent);
    this.setLineW(0.5);
    d.line(PAGE.margin, 34, PAGE.w - PAGE.margin, 34);
    this.y = PAGE.margin + 8;
  };

  PDFBuilder.prototype._drawFooter = function() {
    var d = this.doc;
    var tp = d.internal.getNumberOfPages();
    for (var i = 1; i <= tp; i++) {
      d.setPage(i);
      this.setFont('helvetica', 'normal', FONT_SIZES.micro);
      this.setTColor(COLORS.textSubtle);
      d.text('Generated by mSAS v2  |  ' + new Date().toISOString(), PAGE.margin, PAGE.h - 24);
      d.text('Page ' + i + ' of ' + tp, PAGE.w - PAGE.margin, PAGE.h - 24, { align: 'right' });
    }
  };

  // ── Text Helpers ────────────────────────────────────────────

  /**
   * Write wrapped text at the current y position.
   */
  PDFBuilder.prototype.text = function(str, opts) {
    var o = opts || {};
    var size = o.size || FONT_SIZES.body;
    var style = o.style || 'normal';
    var color = o.color || COLORS.text;
    var lineH = o.lineHeight || (size * 1.4);
    var x = o.x != null ? o.x : CONTENT.x;
    var maxW = o.maxW != null ? o.maxW : CONTENT.w;
    this.setFont('helvetica', style, size);
    this.setTColor(color);
    var text = String(str == null ? '' : str);
    var lines = this.doc.splitTextToSize(text, maxW);
    var totalH = lines.length * lineH;
    this.ensure(totalH + 4);
    this.doc.text(lines, x, this.y);
    this.y += totalH;
    if (o.gap) this.y += o.gap;
    return this;
  };

  /**
   * Write monospace text (for code/matches).
   */
  PDFBuilder.prototype.mono = function(str, opts) {
    var o = opts || {};
    var size = o.size || FONT_SIZES.tiny;
    var lineH = o.lineHeight || (size * 1.4);
    var x = o.x != null ? o.x : CONTENT.x;
    var maxW = o.maxW != null ? o.maxW : CONTENT.w;
    this.setFont('courier', 'normal', size);
    this.setTColor(o.color || COLORS.textMuted);
    var text = String(str == null ? '' : str);
    var lines = this.doc.splitTextToSize(text, maxW);
    var totalH = lines.length * lineH + 8;
    this.ensure(totalH);
    if (o.bg !== false) {
      this.setFill(COLORS.cardBg);
      this.doc.rect(x - 4, this.y, maxW + 8, totalH - 4, 'F');
    }
    this.y += 4;
    for (var li = 0; li < lines.length; li++) {
      this.doc.text(lines[li], x, this.y + lineH - 3);
      this.y += lineH;
    }
    this.y += 4;
    return this;
  };

  /**
   * Draw a horizontal rule.
   */
  PDFBuilder.prototype.rule = function(opts) {
    var o = opts || {};
    var gap = o.gap || 8;
    this.ensure(gap);
    this.setDraw(o.color || COLORS.border);
    this.setLineW(o.width || 0.5);
    this.doc.line(CONTENT.x, this.y, CONTENT.x + CONTENT.w, this.y);
    this.y += gap;
    return this;
  };

  /**
   * Draw a colored badge (pill).
   */
  PDFBuilder.prototype.badge = function(label, color, x, y) {
    var d = this.doc;
    this.setFont('helvetica', 'bold', FONT_SIZES.tiny);
    var w = d.getTextWidth(label) + 12;
    this.setFill(color);
    d.roundedRect(x, y - 9, w, 13, 3, 3, 'F');
    this.setTColor(COLORS.white);
    d.text(label, x + 6, y);
    return w;
  };

  // ── Page Elements ───────────────────────────────────────────

  /**
   * Draw a page title with optional subtitle.
   */
  PDFBuilder.prototype.pageTitle = function(title, subtitle) {
    this.ensure(64);
    this.setFont('helvetica', 'bold', FONT_SIZES.pageTitle);
    this.setTColor(COLORS.text);
    this.doc.text(title, CONTENT.x, this.y);
    this.y += 26;
    if (subtitle) {
      this.setFont('helvetica', 'normal', FONT_SIZES.subHeader);
      this.setTColor(COLORS.textMuted);
      var lines = this.doc.splitTextToSize(subtitle, CONTENT.w);
      this.doc.text(lines, CONTENT.x, this.y);
      this.y += lines.length * 14;
    }
    this.y += 16;
    return this;
  };

  /**
   * Draw a section header with emerald accent bar and optional custom accent color.
   */
  PDFBuilder.prototype.sectionHeader = function(title, accent) {
    this.ensure(36);
    this.y += 8;
    var d = this.doc;
    var accentColor = accent || COLORS.accent;
    this.setFill(accentColor);
    d.rect(CONTENT.x, this.y - 8, 3, 18, 'F');
    this.setFont('helvetica', 'bold', FONT_SIZES.sectionHeader);
    this.setTColor(COLORS.text);
    d.text(title, CONTENT.x + 10, this.y + 6);
    this.y += 22;
    this.setDraw(COLORS.border);
    this.setLineW(0.5);
    d.line(CONTENT.x, this.y, CONTENT.x + CONTENT.w, this.y);
    this.y += 12;
    return this;
  };

  /**
   * Draw a sub-header (smaller than section header, no accent bar).
   */
  PDFBuilder.prototype.subHeader = function(title) {
    this.ensure(20);
    this.y += 6;
    this.setFont('helvetica', 'bold', FONT_SIZES.subHeader);
    this.setTColor(COLORS.text);
    this.doc.text(title, CONTENT.x, this.y);
    this.y += 14;
    return this;
  };

  /**
   * Draw a key-value grid (2 columns by default).
   */
  PDFBuilder.prototype.keyValueGrid = function(items, opts) {
    var o = opts || {};
    var cols = o.cols || 2;
    var gap = 12;
    var colW = (CONTENT.w - gap * (cols - 1)) / cols;
    var rowH = 32;
    var visible = items.filter(function(item) {
      return item[1] != null && item[1] !== '';
    });
    for (var i = 0; i < visible.length; i += cols) {
      this.ensure(rowH + 4);
      for (var c = 0; c < cols; c++) {
        var item = visible[i + c];
        if (!item) continue;
        var x = CONTENT.x + c * (colW + gap);
        var k = item[0], v = item[1];
        var d = this.doc;
        this.setFill(COLORS.cardBg);
        d.roundedRect(x, this.y, colW, rowH - 4, 4, 4, 'F');
        this.setFont('helvetica', 'normal', FONT_SIZES.micro * 0.9);
        this.setTColor(COLORS.textSubtle);
        d.text(String(k).toUpperCase(), x + 8, this.y + 11);
        this.setFont('helvetica', 'normal', FONT_SIZES.body);
        this.setTColor(COLORS.text);
        var valLines = d.splitTextToSize(String(v), colW - 16);
        d.text(valLines[0] || '', x + 8, this.y + 23);
      }
      this.y += rowH;
    }
    return this;
  };

  /**
   * Draw a simple table with headers and rows.
   */
  PDFBuilder.prototype.simpleTable = function(headers, rows, colWidths) {
    var d = this.doc;
    var rowH = 18;
    var totalW = colWidths.reduce(function(s, w) { return s + w; }, 0);
    var scale = totalW > CONTENT.w ? CONTENT.w / totalW : 1;
    var widths = colWidths.map(function(w) { return w * scale; });

    this.ensure(rowH * 2 + 4);
    this.setFill(COLORS.cardBg);
    d.rect(CONTENT.x, this.y, CONTENT.w, rowH, 'F');
    this.setFont('helvetica', 'bold', FONT_SIZES.tiny);
    this.setTColor(COLORS.textMuted);
    var cx = CONTENT.x;
    for (var i = 0; i < headers.length; i++) {
      d.text(headers[i].toUpperCase(), cx + 4, this.y + 12);
      cx += widths[i];
    }
    this.y += rowH;
    this.setDraw(COLORS.border);
    this.setLineW(0.3);

    for (var ri = 0; ri < rows.length; ri++) {
      this.ensure(rowH + 2);
      this.setFont('helvetica', 'normal', FONT_SIZES.tiny * 1.05);
      this.setTColor(COLORS.text);
      var xx = CONTENT.x;
      for (var ci = 0; ci < rows[ri].length; ci++) {
        var cellText = String(rows[ri][ci] == null ? '' : rows[ri][ci]);
        var tLines = d.splitTextToSize(cellText, widths[ci] - 6);
        d.text(tLines[0] || '', xx + 4, this.y + 12);
        xx += widths[ci];
      }
      d.line(CONTENT.x, this.y + rowH, CONTENT.x + CONTENT.w, this.y + rowH);
      this.y += rowH;
    }
    this.y += 4;
    return this;
  };

  /**
   * Draw a check grid (pass/fail indicators).
   */
  PDFBuilder.prototype.checkGrid = function(checks) {
    var cols = 2;
    var gap = 10;
    var colW = (CONTENT.w - gap) / cols;
    var rowH = 26;
    for (var i = 0; i < checks.length; i += cols) {
      this.ensure(rowH + 2);
      for (var c = 0; c < cols; c++) {
        var item = checks[i + c];
        if (!item) continue;
        var name = item[0], ok = item[1];
        var x = CONTENT.x + c * (colW + gap);
        var color = ok ? COLORS.secure : COLORS.high;
        var d = this.doc;
        this.setFill(COLORS.cardBg);
        d.roundedRect(x, this.y, colW, rowH - 4, 4, 4, 'F');
        this.setDraw(color);
        this.setLineW(2);
        d.line(x, this.y + 2, x, this.y + rowH - 6);
        this.setFont('helvetica', 'bold', FONT_SIZES.body);
        this.setTColor(color);
        d.text(ok ? 'OK' : 'NO', x + 10, this.y + 15);
        this.setFont('helvetica', 'normal', FONT_SIZES.small);
        this.setTColor(COLORS.text);
        d.text(name, x + 30, this.y + 15);
      }
      this.y += rowH;
    }
    return this;
  };

  /**
   * Draw a bullet list.
   */
  PDFBuilder.prototype.bulletList = function(items) {
    var d = this.doc;
    for (var i = 0; i < items.length; i++) {
      this.ensure(14);
      this.setFont('helvetica', 'normal', FONT_SIZES.small);
      this.setTColor(COLORS.text);
      var lines = d.splitTextToSize('- ' + String(items[i]), CONTENT.w - 12);
      d.text(lines, CONTENT.x + 6, this.y + 10);
      this.y += lines.length * 12 + 2;
    }
    this.y += 4;
    return this;
  };

  /**
   * Draw a severity bar row (for score breakdown).
   */
  PDFBuilder.prototype.barRow = function(label, count, color, maxVal) {
    this.ensure(22);
    var d = this.doc;
    var barX = CONTENT.x + 110;
    var barW = CONTENT.w - 110 - 50;
    var maxCount = maxVal || 50;
    var fill = Math.min(1, count / maxCount);

    this.setFont('helvetica', 'normal', FONT_SIZES.body);
    this.setTColor(COLORS.text);
    d.text(label, CONTENT.x, this.y + 9);

    this.setFill(COLORS.cardBg);
    d.roundedRect(barX, this.y, barW, 12, 3, 3, 'F');
    if (fill > 0) {
      this.setFill(color);
      d.roundedRect(barX, this.y, Math.max(4, barW * fill), 12, 3, 3, 'F');
    }
    this.setFont('helvetica', 'bold', FONT_SIZES.body);
    this.setTColor(color);
    d.text(String(count), CONTENT.x + CONTENT.w - 4, this.y + 9, { align: 'right' });
    this.y += 18;
    return this;
  };

  // ── Finding Cards ───────────────────────────────────────────

  PDFBuilder.prototype._findingCard = function(group, color) {
    var d = this.doc;
    this.ensure(50);
    var cardX = CONTENT.x;
    var cardW = CONTENT.w;
    var headerH = 30;

    this.setFill(COLORS.cardBg);
    d.roundedRect(cardX, this.y, cardW, headerH, 4, 4, 'F');
    this.setFill(color);
    d.rect(cardX, this.y, 3, headerH, 'F');

    // Severity badge
    var sevW = 60;
    var sevLabel = severityLabel(group.severity || 'info');
    this.setFill(color);
    d.roundedRect(cardX + 10, this.y + 7, sevW, 16, 8, 8, 'F');
    this.setFont('helvetica', 'bold', FONT_SIZES.micro);
    this.setTColor(COLORS.white);
    d.text(sevLabel, cardX + 10 + sevW / 2, this.y + 17, { align: 'center' });

    // Title
    this.setFont('helvetica', 'bold', FONT_SIZES.small * 1.15);
    this.setTColor(COLORS.text);
    var titleX = cardX + 10 + sevW + 6;
    var titleMaxW = cardW - (titleX - cardX) - 110;
    var titleLines = d.splitTextToSize(group.ruleName || group.name || '', titleMaxW);
    d.text(titleLines[0] || group.ruleName || '', titleX, this.y + 19);

    // Instance count
    var instances = group.instances || [];
    var avgConf = group.avgConfidence != null ? group.avgConfidence : 50;
    this.setFont('helvetica', 'normal', FONT_SIZES.tiny * 1.05);
    this.setTColor(COLORS.textMuted);
    var confText = avgConf + '%  /  ' + instances.length + ' ' + (instances.length === 1 ? 'instance' : 'instances');
    d.text(confText, cardX + cardW - 8, this.y + 19, { align: 'right' });

    this.y += headerH + 6;

    // Description
    if (group.description) {
      this.text(group.description, { size: FONT_SIZES.small, color: COLORS.textMuted, gap: 4 });
    }

    // Meta tags (CWE, OWASP, MASVS — for MASTG compliance)
    var meta = [];
    if (group.cwe) meta.push('CWE: ' + group.cwe);
    if (group.owasp) meta.push('OWASP: ' + group.owasp);
    if (group.masvs) meta.push('MASVS: ' + group.masvs);
    if (group.category) meta.push(group.category);
    if (meta.length) {
      this.text(meta.join('   /   '), { size: FONT_SIZES.tiny, color: COLORS.accent, gap: 4 });
    }

    // Instances list
    this.subHeader('Instances (' + instances.length + ')');
    for (var i = 0; i < instances.length; i++) {
      this._instanceRow(i + 1, instances[i], color);
    }
    this.y += 8;
  };

  PDFBuilder.prototype._instanceRow = function(num, inst, color) {
    var d = this.doc;
    this.ensure(34);
    var x = CONTENT.x;
    var w = CONTENT.w;

    this.setFill([252, 252, 253]);
    d.roundedRect(x, this.y, w, 28, 3, 3, 'F');
    this.setDraw(COLORS.border);
    this.setLineW(0.4);
    d.roundedRect(x, this.y, w, 28, 3, 3, 'S');

    // Instance number badge
    this.setFont('helvetica', 'bold', FONT_SIZES.micro);
    this.setFill(color);
    d.roundedRect(x + 8, this.y + 8, 18, 12, 6, 6, 'F');
    this.setTColor(COLORS.white);
    d.text('#' + num, x + 8 + 9, this.y + 16, { align: 'center' });

    // File reference
    var fileX = x + 32;
    var fileLabel = (inst.file || '') + (inst.line ? ':' + inst.line : '');
    this.setFont('courier', 'normal', FONT_SIZES.tiny * 1.05);
    this.setTColor([60, 90, 175]);
    var flLines = d.splitTextToSize(fileLabel, w - 40 - 140);
    d.text(flLines[0] || '', fileX, this.y + 13);

    // Confidence / entropy
    if (inst.confidence != null) {
      this.setFont('helvetica', 'bold', FONT_SIZES.micro);
      this.setTColor(COLORS.textMuted);
      d.text(inst.confidence + '%' + (inst.entropy != null ? '  H=' + inst.entropy : ''), x + w - 8, this.y + 23, { align: 'right' });
    }

    // Match snippet
    this.setFont('courier', 'normal', FONT_SIZES.tiny);
    this.setTColor(COLORS.text);
    var matchLines = d.splitTextToSize(inst.match || '', w - 40 - 140);
    d.text(matchLines[0] || '', fileX, this.y + 23);
    this.y += 32;
  };

  // ── Section Builders ────────────────────────────────────────

  /**
   * Build cover page with security score ring.
   */
  PDFBuilder.prototype.buildCover = function() {
    var r = this.results;
    var d = this.doc;
    var cx = PAGE.w / 2;
    var ai = r.appInfo || r.app || {};

    this.setFill(COLORS.bgAlt);
    d.rect(0, 0, PAGE.w, PAGE.h, 'F');

    // Top emerald accent bar
    this.setFill(COLORS.accent);
    d.rect(0, 0, PAGE.w, 6, 'F');

    // Auditor label
    this.setFont('helvetica', 'bold', FONT_SIZES.coverSubtitle);
    this.setTColor(COLORS.textMuted);
    d.text(this._platformLabel().toUpperCase() + '  /  STATIC SECURITY REPORT', cx, 120, { align: 'center' });

    // App name
    this.setFont('helvetica', 'bold', FONT_SIZES.coverTitle);
    this.setTColor(COLORS.text);
    var appName = ai.appName || ai.name || r.appName || r.package || 'Mobile Application';
    d.text(appName, cx, 180, { align: 'center', maxWidth: 480 });

    // Package / bundle
    this.setFont('helvetica', 'normal', FONT_SIZES.coverSubtitle + 1);
    this.setTColor(COLORS.textMuted);
    var pkg = ai.packageName || ai.bundleId || ai.package || r.packageName || '';
    if (pkg) d.text(pkg, cx, 202, { align: 'center' });

    // Version info
    var verInfo = [];
    if (ai.versionName || ai.version) verInfo.push('v' + (ai.versionName || ai.version));
    if (ai.fileSize) verInfo.push(ai.fileSize);
    if (verInfo.length) {
      d.text(verInfo.join('  ·  '), cx, 220, { align: 'center' });
    }

    // Security score ring
    var score = r.securityScore != null ? r.securityScore : (r.score != null ? r.score : 0);
    var sColor = scoreColor(score);
    var sLabel = scoreGrade(score);
    this.setDraw(sColor);
    this.setLineW(8);
    d.circle(cx, 350, 65);
    this.setFont('helvetica', 'bold', 46);
    this.setTColor(sColor);
    d.text(String(Math.round(score)), cx, 362, { align: 'center' });
    this.setFont('helvetica', 'normal', FONT_SIZES.body);
    this.setTColor(COLORS.textMuted);
    d.text('/ 100', cx, 378, { align: 'center' });
    this.setFont('helvetica', 'bold', FONT_SIZES.sectionHeader);
    this.setTColor(sColor);
    d.text(sLabel.toUpperCase(), cx, 440, { align: 'center' });

    // Stats cards
    var sum = r.summary || {};
    var stats = [
      { label: 'ISSUES',  val: sum.issue || sum.high || 0,  color: COLORS.high },
      { label: 'SECURE',  val: sum.secure || sum.pass || 0, color: COLORS.secure },
      { label: 'INFO',    val: sum.info || 0,               color: COLORS.low },
      { label: 'TOTAL',   val: sum.total || r.total || 0,   color: COLORS.accent },
    ];
    var sw = 100, sgap = 12;
    var totalW = sw * 4 + sgap * 3;
    var sx0 = cx - totalW / 2;
    var sy = 480;
    for (var si = 0; si < stats.length; si++) {
      var s = stats[si];
      var sx = sx0 + si * (sw + sgap);
      this.setFill(COLORS.white);
      this.setDraw(COLORS.border);
      d.setLineWidth(0.5);
      d.roundedRect(sx, sy, sw, 56, 6, 6, 'FD');
      this.setFont('helvetica', 'bold', 22);
      this.setTColor(s.color);
      d.text(String(s.val), sx + sw / 2, sy + 30, { align: 'center' });
      this.setFont('helvetica', 'normal', FONT_SIZES.tiny);
      this.setTColor(COLORS.textMuted);
      d.text(s.label, sx + sw / 2, sy + 46, { align: 'center' });
    }

    // Metadata
    var metaItems = [];
    if (pkg) metaItems.push([pkg.indexOf('.') > 0 ? 'Package' : 'Bundle', pkg]);
    if (ai.minSdk != null) metaItems.push(['Min SDK', 'API ' + ai.minSdk]);
    if (ai.targetSdk != null) metaItems.push(['Target SDK', 'API ' + ai.targetSdk]);
    if (ai.fileSize) metaItems.push(['File', ai.fileSize]);
    metaItems.push(['Scanned', new Date().toISOString()]);

    var my = 580;
    this.setFontSize(FONT_SIZES.small);
    for (var mi = 0; mi < metaItems.length; mi++) {
      if (!metaItems[mi][1]) continue;
      this.setFont('helvetica', 'normal');
      this.setTColor(COLORS.textMuted);
      d.text(metaItems[mi][0], PAGE.margin + 40, my);
      this.setFont('helvetica', 'normal');
      this.setTColor(COLORS.text);
      d.text(String(metaItems[mi][1]), PAGE.margin + 140, my);
      my += 16;
    }

    // SHA-256
    if (ai.sha256) {
      this.setFont('helvetica', 'normal', FONT_SIZES.micro);
      this.setTColor(COLORS.textSubtle);
      d.text('SHA-256: ' + ai.sha256, cx, PAGE.h - 60, { align: 'center', maxWidth: 480 });
    }

    // Disclaimer
    this.setFont('helvetica', 'italic', FONT_SIZES.tiny);
    this.setTColor(COLORS.textSubtle);
    d.text('Automated static analysis. OWASP MASVS aligned. Findings are indicative.', cx, PAGE.h - 40, { align: 'center', maxWidth: 480 });
    d.text('Manual triage by a qualified security professional is required.', cx, PAGE.h - 28, { align: 'center', maxWidth: 480 });
  };

  /**
   * Build executive summary page.
   */
  PDFBuilder.prototype.buildSummary = function() {
    this.addPage();
    var r = this.results;
    var ai = r.appInfo || r.app || {};

    this.pageTitle('Executive Summary', 'High-level overview of static analysis findings.');

    this.sectionHeader('Application');
    var grid = [
      ['Name',   ai.appName || ai.name || r.appName],
      ['Type',   this._platformLabel()],
    ];
    if (ai.packageName || ai.bundleId) {
      grid.push(['Package', ai.packageName || ai.bundleId]);
    }
    if (ai.versionName || ai.version) {
      grid.push(['Version', ai.versionName || ai.version]);
    }
    if (ai.minSdk != null) grid.push(['Min SDK', 'API ' + ai.minSdk]);
    if (ai.targetSdk != null) grid.push(['Target', 'API ' + ai.targetSdk]);
    if (ai.fileSize) grid.push(['Size', ai.fileSize]);
    this.keyValueGrid(grid);

    // Security score breakdown
    this.sectionHeader('Security Score');
    var score = r.securityScore != null ? r.securityScore : (r.score != null ? r.score : 0);
    this.text('Score: ' + Math.round(score) + '/100  ·  Grade: ' + scoreGrade(score), { size: FONT_SIZES.small, color: COLORS.textMuted, gap: 6 });

    var sum = r.summary || {};
    var maxVal = Math.max(1, sum.high || 0, sum.issue || 0, sum.medium || 0, sum.low || 0, sum.info || 0);
    if (maxVal > 0) {
      if (sum.high || sum.issue) this.barRow('High', (sum.high || 0) + (sum.issue || 0), COLORS.high, maxVal);
      if (sum.medium) this.barRow('Medium', sum.medium, COLORS.medium, maxVal);
      if (sum.low || sum.info) this.barRow('Info', (sum.low || 0) + (sum.info || 0), COLORS.low, maxVal);
      if (sum.secure || sum.pass) this.barRow('Secure', (sum.secure || 0) + (sum.pass || 0), COLORS.secure, maxVal);
    }

    // Findings count
    var findingsCount = r.totalFindings || 0;
    if (!findingsCount && r.groupedFindings) {
      for (var key in r.groupedFindings) {
        if (r.groupedFindings.hasOwnProperty(key)) {
          findingsCount += (r.groupedFindings[key] || []).length;
        }
      }
    }
    if (r.trackers && r.trackers.length) {
      this.sectionHeader('Trackers & SDKs');
      var trackerNames = (r.trackers || []).map(function(t) {
        return typeof t === 'string' ? t : (t.name || t);
      });
      this.text(trackerNames.join(', '), { size: FONT_SIZES.small, color: COLORS.textMuted });
    }
  };

  /**
   * Build findings section pages.
   */
  PDFBuilder.prototype.buildFindings = function() {
    var r = this.results;
    this.addPage();
    this.pageTitle('Findings', 'All detected rules with instances. Severities: Critical, High, Medium, Low, Info, Secure.');

    var sections = [
      { key: 'critical', color: COLORS.critical, title: 'Critical' },
      { key: 'issue',    color: COLORS.high,     title: 'High Severity' },
      { key: 'high',     color: COLORS.high,     title: 'High Severity' },
      { key: 'medium',   color: COLORS.medium,   title: 'Medium' },
      { key: 'warning',  color: COLORS.medium,   title: 'Medium' },
      { key: 'low',      color: COLORS.low,      title: 'Low' },
      { key: 'info',     color: COLORS.info,     title: 'Informational' },
      { key: 'secure',   color: COLORS.secure,   title: 'Secure Controls' },
      { key: 'pass',     color: COLORS.secure,   title: 'Passed Checks' },
    ];

    var rendered = false;
    for (var si = 0; si < sections.length; si++) {
      var sec = sections[si];
      var groups = [];
      if (r.groupedFindings && r.groupedFindings[sec.key]) {
        groups = r.groupedFindings[sec.key];
      }
      if (!groups.length) continue;

      rendered = true;
      this.sectionHeader(sec.title + '  (' + groups.length + ')', sec.color);
      for (var gi = 0; gi < groups.length; gi++) {
        this._findingCard(groups[gi], sec.color);
      }
    }

    // Also handle flat findings array
    if (!rendered && r.findings && r.findings.length) {
      var bySeverity = {};
      for (var fi = 0; fi < r.findings.length; fi++) {
        var f = r.findings[fi];
        var sevKey = f.severity || 'info';
        if (!bySeverity[sevKey]) bySeverity[sevKey] = [];
        bySeverity[sevKey].push(f);
      }
      for (var sevName in bySeverity) {
        if (bySeverity.hasOwnProperty(sevName)) {
          var sevColor = severityColor(sevName);
          var sevTitle = sevName.charAt(0).toUpperCase() + sevName.slice(1);
          this.sectionHeader(sevTitle + '  (' + bySeverity[sevName].length + ')', sevColor);
          for (var fi2 = 0; fi2 < bySeverity[sevName].length; fi2++) {
            var ff = bySeverity[sevName][fi2];
            this._findingCard({
              ruleName: ff.title || ff.ruleName || ff.name,
              severity: ff.severity,
              description: ff.description,
              cwe: ff.cwe,
              owasp: ff.owasp,
              masvs: ff.masvs || ff.mastgRef,
              category: ff.category,
              instances: ff.instances || (ff.file ? [{ file: ff.file, line: ff.line, match: ff.match, confidence: ff.confidence, entropy: ff.entropy }] : []),
              avgConfidence: ff.confidence
            }, sevColor);
          }
        }
      }
      rendered = true;
    }

    if (!rendered) {
      this.text('No findings to report.', { color: COLORS.textMuted, size: FONT_SIZES.small });
    }
  };

  // ── Platform Info ────────────────────────────────────────────

  PDFBuilder.prototype._platformLabel = function() {
    var map = {
      apk:  'APK Auditor',
      ipa:  'IPA Auditor',
      adb:  'ADB Auditor',
      android: 'APK Auditor',
      ios:  'IPA Auditor'
    };
    return map[this._platform] || 'mSAS v2 Security Report';
  };

  PDFBuilder.prototype._getAppName = function() {
    var r = this.results;
    var ai = r.appInfo || r.app || {};
    return ai.appName || ai.name || r.appName || r.package || '';
  };

  // ── Main Build ──────────────────────────────────────────────

  /**
   * Build the complete PDF report.
   *
   * @param {Object} results - Analysis results (supports APK, IPA, and ADB result formats)
   * @param {Object} [opts] - Options
   * @param {string} [opts.platform='generic'] - Platform: 'apk', 'ipa', 'adb', or 'generic'
   * @param {string} [opts.appName] - Override app name
   * @param {boolean} [opts.skipCover=false] - Skip cover page
   * @param {boolean} [opts.skipSummary=false] - Skip summary page
   * @param {boolean} [opts.skipFindings=false] - Skip findings section
   * @returns {Object} jsPDF document instance
   */
  PDFBuilder.prototype.build = function(results, opts) {
    this._init(results, opts);

    // Cover page
    if (!opts || !opts.skipCover) {
      this.buildCover();
    }

    // Summary
    if (!opts || !opts.skipSummary) {
      this.buildSummary();
    }

    // Findings
    if (!opts || !opts.skipFindings) {
      this.buildFindings();
    }

    // Footer on all pages
    this._drawFooter();

    return this.doc;
  };

  // ── Convenience Export ──────────────────────────────────────

  /**
   * Export a complete executive PDF report.
   * Handles jsPDF availability and creates a downloadable blob.
   *
   * @param {Object} results - Analysis results
   * @param {Object} [opts] - Options (same as PDFBuilder.build)
   * @param {string} [opts.filename] - Optional filename (without extension)
   * @returns {Blob|null} PDF blob, or null if jsPDF unavailable
   */
  function exportExecutiveReport(results, opts) {
    opts = opts || {};
    try {
      var builder = new PDFBuilder();
      var doc = builder.build(results, opts);

      // Generate filename
      var ai = (results && (results.appInfo || results.app)) || {};
      var base = opts.filename || ai.packageName || ai.bundleId || ai.fileName || results.package || 'security-report';
      var safe = String(base).replace(/[^a-zA-Z0-9._-]/g, '_');
      var filename = safe + '_audit.pdf';

      // Trigger browser download
      doc.save(filename);
      return doc.output('blob');
    } catch (e) {
      console.error('[SharedPdf] Failed to generate PDF:', e.message);
      return null;
    }
  }

  /**
   * Generate a PDF blob (for server-side or programmatic use).
   */
  function generatePdfBlob(results, opts) {
    try {
      var builder = new PDFBuilder();
      var doc = builder.build(results, opts);
      return doc.output('blob');
    } catch (e) {
      console.error('[SharedPdf] Failed to generate PDF blob:', e.message);
      return null;
    }
  }

  // ── Public API ──────────────────────────────────────────────

  return {
    PDFBuilder: PDFBuilder,
    exportExecutiveReport: exportExecutiveReport,
    generatePdfBlob: generatePdfBlob,
    COLORS: COLORS,
    severityColor: severityColor,
    severityLabel: severityLabel,
    scoreColor: scoreColor,
    scoreGrade: scoreGrade
  };
})();
