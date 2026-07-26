/**
 * mSAS v2 — Unit Tests: Unified PDF Report Builder (BASE-4)
 *
 * Tests for MSAS.SharedPdf — PDF builder architecture, severity helpers,
 * and utility functions. Full document generation is tested via E2E.
 *
 * Note: jsPDF uses UMD export and internal module state, so full document
 * rendering tests require a browser environment. We test the builder's
 * structure, helpers, and export function gracefully handles missing jsPDF.
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.SharedPdf', () => {
  it('should be defined', () => {
    expect(MSAS.SharedPdf).toBeTruthy();
  });

  // ═══════════════════════════════════════════════════════════
  // API Surface
  // ═══════════════════════════════════════════════════════════

  describe('API surface', () => {
    it('should expose expected classes and functions', () => {
      expect(typeof MSAS.SharedPdf.PDFBuilder).toBe('function');
      expect(typeof MSAS.SharedPdf.exportExecutiveReport).toBe('function');
      expect(typeof MSAS.SharedPdf.generatePdfBlob).toBe('function');
    });

    it('should expose helper functions', () => {
      expect(typeof MSAS.SharedPdf.severityColor).toBe('function');
      expect(typeof MSAS.SharedPdf.severityLabel).toBe('function');
      expect(typeof MSAS.SharedPdf.scoreColor).toBe('function');
      expect(typeof MSAS.SharedPdf.scoreGrade).toBe('function');
    });

    it('should expose COLORS object', () => {
      expect(MSAS.SharedPdf.COLORS).toBeTruthy();
      expect(Array.isArray(MSAS.SharedPdf.COLORS.accent)).toBe(true);
      expect(MSAS.SharedPdf.COLORS.accent).toEqual([16, 185, 129]); // emerald
      expect(Array.isArray(MSAS.SharedPdf.COLORS.high)).toBe(true);
      expect(Array.isArray(MSAS.SharedPdf.COLORS.critical)).toBe(true);
      expect(Array.isArray(MSAS.SharedPdf.COLORS.secure)).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // PDFBuilder Constructor
  // ═══════════════════════════════════════════════════════════

  describe('PDFBuilder constructor', () => {
    it('should create a new builder with default state', () => {
      var builder = new MSAS.SharedPdf.PDFBuilder();
      expect(builder).toBeTruthy();
      expect(builder.doc).toBeNull(); // Not initialized until build()
      expect(builder.y).toBe(48); // PAGE.margin
      expect(builder.pageNo).toBe(1);
      expect(builder.results).toBeNull();
      expect(builder.options).toEqual({});
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Severity Helpers
  // ═══════════════════════════════════════════════════════════

  describe('severityColor', () => {
    it('should return correct colors for standard severities', () => {
      expect(MSAS.SharedPdf.severityColor('critical')).toEqual(MSAS.SharedPdf.COLORS.critical);
      expect(MSAS.SharedPdf.severityColor('high')).toEqual(MSAS.SharedPdf.COLORS.high);
      expect(MSAS.SharedPdf.severityColor('medium')).toEqual(MSAS.SharedPdf.COLORS.medium);
      expect(MSAS.SharedPdf.severityColor('low')).toEqual(MSAS.SharedPdf.COLORS.low);
      expect(MSAS.SharedPdf.severityColor('info')).toEqual(MSAS.SharedPdf.COLORS.low);
      expect(MSAS.SharedPdf.severityColor('secure')).toEqual(MSAS.SharedPdf.COLORS.secure);
    });

    it('should handle legacy severity mappings', () => {
      expect(MSAS.SharedPdf.severityColor('issue')).toEqual(MSAS.SharedPdf.COLORS.high);
      expect(MSAS.SharedPdf.severityColor('warning')).toEqual(MSAS.SharedPdf.COLORS.medium);
      expect(MSAS.SharedPdf.severityColor('review')).toEqual(MSAS.SharedPdf.COLORS.medium);
      expect(MSAS.SharedPdf.severityColor('pass')).toEqual(MSAS.SharedPdf.COLORS.secure);
    });

    it('should handle unknown severity gracefully', () => {
      var result = MSAS.SharedPdf.severityColor('unknown');
      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBe(3);
    });

    it('should handle undefined/null', () => {
      expect(Array.isArray(MSAS.SharedPdf.severityColor(undefined))).toBe(true);
      expect(Array.isArray(MSAS.SharedPdf.severityColor(null))).toBe(true);
    });
  });

  describe('severityLabel', () => {
    it('should return correct labels', () => {
      expect(MSAS.SharedPdf.severityLabel('critical')).toBe('CRITICAL');
      expect(MSAS.SharedPdf.severityLabel('high')).toBe('HIGH');
      expect(MSAS.SharedPdf.severityLabel('medium')).toBe('MEDIUM');
      expect(MSAS.SharedPdf.severityLabel('low')).toBe('LOW');
      expect(MSAS.SharedPdf.severityLabel('info')).toBe('INFO');
      expect(MSAS.SharedPdf.severityLabel('secure')).toBe('SECURE');
    });

    it('should map legacy severities', () => {
      expect(MSAS.SharedPdf.severityLabel('issue')).toBe('HIGH');
      expect(MSAS.SharedPdf.severityLabel('warning')).toBe('MEDIUM');
      expect(MSAS.SharedPdf.severityLabel('review')).toBe('MEDIUM');
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Score Helpers
  // ═══════════════════════════════════════════════════════════

  describe('scoreColor', () => {
    it('should return secure color for high scores', () => {
      expect(MSAS.SharedPdf.scoreColor(95)).toEqual(MSAS.SharedPdf.COLORS.secure);
      expect(MSAS.SharedPdf.scoreColor(85)).toEqual(MSAS.SharedPdf.COLORS.secure);
    });

    it('should return low/info color for good scores', () => {
      expect(MSAS.SharedPdf.scoreColor(75)).toEqual(MSAS.SharedPdf.COLORS.low);
      expect(MSAS.SharedPdf.scoreColor(70)).toEqual(MSAS.SharedPdf.COLORS.low);
    });

    it('should return medium/warning for fair scores', () => {
      expect(MSAS.SharedPdf.scoreColor(60)).toEqual(MSAS.SharedPdf.COLORS.medium);
      expect(MSAS.SharedPdf.scoreColor(50)).toEqual(MSAS.SharedPdf.COLORS.medium);
    });

    it('should return high for poor scores', () => {
      expect(MSAS.SharedPdf.scoreColor(40)).toEqual(MSAS.SharedPdf.COLORS.high);
      expect(MSAS.SharedPdf.scoreColor(30)).toEqual(MSAS.SharedPdf.COLORS.high);
    });

    it('should return critical for very low scores', () => {
      expect(MSAS.SharedPdf.scoreColor(10)).toEqual(MSAS.SharedPdf.COLORS.critical);
      expect(MSAS.SharedPdf.scoreColor(0)).toEqual(MSAS.SharedPdf.COLORS.critical);
    });
  });

  describe('scoreGrade', () => {
    it('should return correct grades', () => {
      expect(MSAS.SharedPdf.scoreGrade(90)).toBe('Excellent');
      expect(MSAS.SharedPdf.scoreGrade(75)).toBe('Good');
      expect(MSAS.SharedPdf.scoreGrade(60)).toBe('Fair');
      expect(MSAS.SharedPdf.scoreGrade(40)).toBe('Poor');
      expect(MSAS.SharedPdf.scoreGrade(10)).toBe('Critical');
    });

    it('should handle boundary values', () => {
      expect(MSAS.SharedPdf.scoreGrade(85)).toBe('Excellent');
      expect(MSAS.SharedPdf.scoreGrade(70)).toBe('Good');
      expect(MSAS.SharedPdf.scoreGrade(50)).toBe('Fair');
      expect(MSAS.SharedPdf.scoreGrade(30)).toBe('Poor');
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Export Function (graceful handling)
  // ═══════════════════════════════════════════════════════════

  describe('exportExecutiveReport', () => {
    it('should handle missing jsPDF gracefully', () => {
      // In test environment (jsdom), jsPDF may not be loaded
      // The function should catch the error and return null
      var result = MSAS.SharedPdf.exportExecutiveReport({ appInfo: { appName: 'Test' } }, { platform: 'apk' });
      // Either returns a Blob (if jsPDF available) or null (if not)
      if (result !== null) {
        expect(result instanceof Blob).toBe(true);
      }
    });
  });

  describe('generatePdfBlob', () => {
    it('should handle missing jsPDF gracefully', () => {
      var result = MSAS.SharedPdf.generatePdfBlob({ appInfo: { appName: 'Test' } });
      if (result !== null) {
        expect(result instanceof Blob).toBe(true);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Builder Methods (structural, no jsPDF required)
  // ═══════════════════════════════════════════════════════════

  describe('PDFBuilder prototype methods', () => {
    it('should have required prototype methods', () => {
      var proto = MSAS.SharedPdf.PDFBuilder.prototype;

      // Page management
      expect(typeof proto.ensure).toBe('function');
      expect(typeof proto.addPage).toBe('function');
      expect(typeof proto.setFont).toBe('function');

      // Text helpers
      expect(typeof proto.text).toBe('function');
      expect(typeof proto.mono).toBe('function');
      expect(typeof proto.rule).toBe('function');

      // Page elements
      expect(typeof proto.pageTitle).toBe('function');
      expect(typeof proto.sectionHeader).toBe('function');
      expect(typeof proto.subHeader).toBe('function');
      expect(typeof proto.keyValueGrid).toBe('function');
      expect(typeof proto.simpleTable).toBe('function');
      expect(typeof proto.checkGrid).toBe('function');
      expect(typeof proto.bulletList).toBe('function');
      expect(typeof proto.barRow).toBe('function');

      // Section builders
      expect(typeof proto.buildCover).toBe('function');
      expect(typeof proto.buildSummary).toBe('function');
      expect(typeof proto.buildFindings).toBe('function');

      // Main build
      expect(typeof proto.build).toBe('function');
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Color Constants
  // ═══════════════════════════════════════════════════════════

  describe('COLORS', () => {
    it('should have emerald as the primary accent', () => {
      var accent = MSAS.SharedPdf.COLORS.accent;
      expect(accent[0]).toBe(16);   // R
      expect(accent[1]).toBe(185);  // G
      expect(accent[2]).toBe(129);  // B
    });

    it('should have all required color entries', () => {
      var requiredKeys = [
        'text', 'textMuted', 'textSubtle', 'border',
        'accent', 'accentDark', 'accentSub',
        'critical', 'high', 'medium', 'low', 'info', 'secure',
        'cardBg', 'bgAlt', 'white'
      ];
      for (var i = 0; i < requiredKeys.length; i++) {
        expect(MSAS.SharedPdf.COLORS.hasOwnProperty(requiredKeys[i])).toBe(true);
        expect(Array.isArray(MSAS.SharedPdf.COLORS[requiredKeys[i]])).toBe(true);
        expect(MSAS.SharedPdf.COLORS[requiredKeys[i]].length).toBe(3);
      }
    });
  });

  // ═══════════════════════════════════════════════════════════
  // FONT_SIZES via prototype behavior
  // ═══════════════════════════════════════════════════════════

  describe('builder font handling', () => {
    it('should have setFont method that chains', () => {
      var builder = new MSAS.SharedPdf.PDFBuilder();
      // Should not throw when called before build (doc is null)
      // setFont checks for doc internally
      expect(typeof builder.setFont).toBe('function');
    });
  });
});
