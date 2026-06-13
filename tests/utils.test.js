/**
 * mSAS v2 — Unit Tests: Utils & TestResult
 * 
 * Tests for MSAS.Utils helpers and MSAS.TestResult schema.
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.Utils', () => {
  describe('escapeHtml', () => {
    it('should escape HTML special characters', () => {
      const result = MSAS.Utils.escapeHtml('<script>alert("xss")</script>');
      // In jsdom textContent doesn't double-encode quotes — just verify angle brackets are escaped
      expect(result).toContain('&lt;script&gt;');
      expect(result).toContain('&lt;/script&gt;');
    });

    it('should return empty string for null/undefined input', () => {
      expect(MSAS.Utils.escapeHtml(null)).toBe('');
      expect(MSAS.Utils.escapeHtml(undefined)).toBe('');
    });

    it('should return plain text unchanged', () => {
      expect(MSAS.Utils.escapeHtml('Hello, world!')).toBe('Hello, world!');
    });

    it('should escape ampersands', () => {
      expect(MSAS.Utils.escapeHtml('A & B')).toBe('A &amp; B');
    });
  });

  describe('formatBytes', () => {
    it('should format bytes', () => {
      expect(MSAS.Utils.formatBytes(0)).toBe('0 B');
      expect(MSAS.Utils.formatBytes(500)).toBe('500.0 B');
    });

    it('should format kilobytes', () => {
      expect(MSAS.Utils.formatBytes(2048)).toBe('2.0 KB');
    });

    it('should format megabytes', () => {
      expect(MSAS.Utils.formatBytes(1048576)).toBe('1.0 MB');
    });

    it('should handle null/undefined', () => {
      expect(MSAS.Utils.formatBytes(null)).toBe('0 B');
    });
  });

  describe('formatDate', () => {
    it('should format date to ISO string', () => {
      const result = MSAS.Utils.formatDate(new Date('2024-01-15T10:30:00Z'));
      expect(result).toBe('2024-01-15T10:30:00.000Z');
    });

    it('should show relative time for recent dates', () => {
      const now = new Date();
      const result = MSAS.Utils.formatDate(now, true);
      expect(result).toBe('just now');
    });
  });

  describe('deepClone', () => {
    it('should deep clone an object', () => {
      const obj = { a: 1, b: { c: [1, 2, 3] } };
      const cloned = MSAS.Utils.deepClone(obj);
      expect(cloned).toEqual(obj);
      expect(cloned).not.toBe(obj);
      expect(cloned.b).not.toBe(obj.b);
    });
  });

  describe('debounce', () => {
    it('should debounce function calls', async () => {
      let callCount = 0;
      const fn = MSAS.Utils.debounce(() => { callCount++; }, 50);
      fn();
      fn();
      fn();
      expect(callCount).toBe(0);
      await new Promise(resolve => setTimeout(resolve, 100));
      expect(callCount).toBe(1);
    });
  });

  describe('groupBy', () => {
    it('should group items by a key field', () => {
      const items = [
        { severity: 'high', title: 'A' },
        { severity: 'low', title: 'B' },
        { severity: 'high', title: 'C' },
      ];
      const grouped = MSAS.Utils.groupBy(items, 'severity');
      expect(grouped.high).toHaveLength(2);
      expect(grouped.low).toHaveLength(1);
    });
  });

  describe('countBySeverity', () => {
    it('should count findings by severity', () => {
      const findings = [
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'medium' },
        { severity: 'critical' },
        { severity: 'info' },
        { severity: 'low' },
      ];
      const counts = MSAS.Utils.countBySeverity(findings);
      expect(counts.critical).toBe(2);
      expect(counts.high).toBe(1);
      expect(counts.medium).toBe(1);
      expect(counts.low).toBe(1);
      expect(counts.info).toBe(1);
    });

    it('should handle empty array', () => {
      const counts = MSAS.Utils.countBySeverity([]);
      expect(counts.critical).toBe(0);
    });
  });

  describe('uid', () => {
    it('should generate unique IDs', () => {
      const id1 = MSAS.Utils.uid();
      const id2 = MSAS.Utils.uid();
      expect(id1).toMatch(/^msas-/);
      expect(id1).not.toBe(id2);
    });
  });

  describe('findInStrings', () => {
    it('should find matching signatures in string array', () => {
      const strings = ['hello world', 'test android.database.sqlite', 'goodbye'];
      const signatures = ['sqlite', 'realm'];
      const found = MSAS.Utils.findInStrings(strings, signatures);
      expect(found).toEqual(['sqlite']);
    });

    it('should return empty array when no matches', () => {
      const strings = ['hello', 'world'];
      const signatures = ['sqlite'];
      expect(MSAS.Utils.findInStrings(strings, signatures)).toEqual([]);
    });
  });

  describe('hasInStrings', () => {
    it('should return true when signature found', () => {
      expect(MSAS.Utils.hasInStrings(['test WebView'], ['WebView'])).toBe(true);
    });

    it('should return false when signature not found', () => {
      expect(MSAS.Utils.hasInStrings(['hello'], ['WebView'])).toBe(false);
    });
  });
});

describe('MSAS.TestResult', () => {
  describe('create', () => {
    it('should create a valid finding with all fields', () => {
      const result = MSAS.TestResult.create({
        id: 'test-1',
        title: 'Test Finding',
        description: 'A test finding',
        cvss: 7.5,
        category: MSAS.TestResult.CATEGORIES.STORAGE,
        mastgRef: 'MASTG-STORAGE-1',
        remediation: 'Fix it',
        detail: 'extra detail',
      });

      expect(result.id).toBe('test-1');
      expect(result.title).toBe('Test Finding');
      expect(result.severity).toBe('high');
      expect(result.cvss).toBe(7.5);
      expect(result.category).toBe('storage');
      expect(result.mastgRef).toBe('MASTG-STORAGE-1');
      expect(result.remediation).toBe('Fix it');
      expect(result.detail).toBe('extra detail');
      expect(result.passed).toBe(false);
      expect(result.timestamp).toBeTruthy();
    });

    it('should create a passed finding', () => {
      const result = MSAS.TestResult.create({ passed: true });
      expect(result.passed).toBe(true);
    });

    it('should set defaults for missing fields', () => {
      const result = MSAS.TestResult.create({});
      expect(result.id).toMatch(/^msas-/);
      expect(result.title).toBe('Untitled Finding');
      expect(result.severity).toBe('info');
      expect(result.cvss).toBe(0);
    });
  });

  describe('severityOf', () => {
    it('should return critical for score >= 9.0', () => {
      expect(MSAS.TestResult.severityOf(9.0)).toBe('critical');
      expect(MSAS.TestResult.severityOf(10)).toBe('critical');
    });

    it('should return high for score >= 7.0', () => {
      expect(MSAS.TestResult.severityOf(7.0)).toBe('high');
      expect(MSAS.TestResult.severityOf(8.9)).toBe('high');
    });

    it('should return medium for score >= 4.0', () => {
      expect(MSAS.TestResult.severityOf(4.0)).toBe('medium');
      expect(MSAS.TestResult.severityOf(6.9)).toBe('medium');
    });

    it('should return low for score >= 1.0', () => {
      expect(MSAS.TestResult.severityOf(1.0)).toBe('low');
      expect(MSAS.TestResult.severityOf(3.9)).toBe('low');
    });

    it('should return info for score < 1.0', () => {
      expect(MSAS.TestResult.severityOf(0)).toBe('info');
      expect(MSAS.TestResult.severityOf(0.5)).toBe('info');
    });

    it('should clamp out-of-range scores', () => {
      expect(MSAS.TestResult.severityOf(-1)).toBe('info');
      expect(MSAS.TestResult.severityOf(15)).toBe('critical');
    });
  });

  describe('scoreOf', () => {
    it('should return numeric score for severity label', () => {
      expect(MSAS.TestResult.scoreOf('critical')).toBe(10);
      expect(MSAS.TestResult.scoreOf('high')).toBe(8);
      expect(MSAS.TestResult.scoreOf('medium')).toBe(5);
      expect(MSAS.TestResult.scoreOf('low')).toBe(2);
      expect(MSAS.TestResult.scoreOf('info')).toBe(0);
    });

    it('should return 0 for unknown label', () => {
      expect(MSAS.TestResult.scoreOf('unknown')).toBe(0);
    });
  });

  describe('severityClass', () => {
    it('should return correct CSS class', () => {
      expect(MSAS.TestResult.severityClass('critical')).toBe('severity-critical');
      expect(MSAS.TestResult.severityClass('info')).toBe('severity-info');
    });
  });

  describe('CATEGORIES', () => {
    it('should have all defined categories', () => {
      expect(MSAS.TestResult.CATEGORIES.STORAGE).toBe('storage');
      expect(MSAS.TestResult.CATEGORIES.CRYPTO).toBe('cryptography');
      expect(MSAS.TestResult.CATEGORIES.AUTH).toBe('authentication');
      expect(MSAS.TestResult.CATEGORIES.NETWORK).toBe('network');
      expect(MSAS.TestResult.CATEGORIES.PLATFORM).toBe('platform');
      expect(MSAS.TestResult.CATEGORIES.CODE).toBe('code_quality');
      expect(MSAS.TestResult.CATEGORIES.RESILIENCE).toBe('resilience');
      expect(MSAS.TestResult.CATEGORIES.AI_ML).toBe('ai_ml');
    });
  });
});
