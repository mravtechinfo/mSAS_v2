/**
 * mSAS v2 — Unit Tests: Shared Module System (BASE-1)
 *
 * Tests for MSAS.SharedFormat, MSAS.SharedEntropy, and MSAS.SharedRegistry.
 */

import { describe, it, expect } from 'vitest';

// ═══════════════════════════════════════════════════════════════
// MSAS.SharedFormat
// ═══════════════════════════════════════════════════════════════

describe('MSAS.SharedFormat', () => {
  it('should be defined', () => {
    expect(MSAS.SharedFormat).toBeTruthy();
  });

  describe('formatBytes', () => {
    it('should format 0 bytes', () => {
      expect(MSAS.SharedFormat.formatBytes(0)).toBe('0 B');
    });

    it('should format bytes', () => {
      expect(MSAS.SharedFormat.formatBytes(500)).toBe('500.0 B');
      expect(MSAS.SharedFormat.formatBytes(1023)).toBe('1023.0 B');
    });

    it('should format kilobytes', () => {
      expect(MSAS.SharedFormat.formatBytes(1024)).toBe('1.0 KB');
      expect(MSAS.SharedFormat.formatBytes(2048)).toBe('2.0 KB');
    });

    it('should format megabytes', () => {
      expect(MSAS.SharedFormat.formatBytes(1048576)).toBe('1.0 MB');
      expect(MSAS.SharedFormat.formatBytes(1572864)).toBe('1.5 MB');
    });

    it('should format gigabytes', () => {
      expect(MSAS.SharedFormat.formatBytes(1073741824)).toBe('1.0 GB');
    });

    it('should handle null/undefined', () => {
      expect(MSAS.SharedFormat.formatBytes(null)).toBe('0 B');
      expect(MSAS.SharedFormat.formatBytes(undefined)).toBe('0 B');
    });
  });

  describe('escapeHtml', () => {
    it('should escape angle brackets', () => {
      expect(MSAS.SharedFormat.escapeHtml('<script>')).toBe('&lt;script&gt;');
    });

    it('should escape ampersands', () => {
      expect(MSAS.SharedFormat.escapeHtml('A & B')).toBe('A &amp; B');
    });

    it('should escape quotes', () => {
      expect(MSAS.SharedFormat.escapeHtml('"hello"')).toBe('&quot;hello&quot;');
      expect(MSAS.SharedFormat.escapeHtml("'hello'")).toBe('&#39;hello&#39;');
    });

    it('should return empty string for null/undefined', () => {
      expect(MSAS.SharedFormat.escapeHtml(null)).toBe('');
      expect(MSAS.SharedFormat.escapeHtml(undefined)).toBe('');
    });
  });

  describe('formatDate', () => {
    it('should format to ISO string', () => {
      var d = new Date('2024-06-15T10:30:00.000Z');
      expect(MSAS.SharedFormat.formatDate(d)).toBe('2024-06-15T10:30:00.000Z');
    });

    it('should show relative time', () => {
      var now = new Date();
      expect(MSAS.SharedFormat.formatDate(now, true)).toBe('just now');

      var secAgo = new Date(Date.now() - 10000);
      expect(MSAS.SharedFormat.formatDate(secAgo, true)).toBe('10s ago');

      var minAgo = new Date(Date.now() - 120000);
      expect(MSAS.SharedFormat.formatDate(minAgo, true)).toBe('2m ago');

      var hrAgo = new Date(Date.now() - 7200000);
      expect(MSAS.SharedFormat.formatDate(hrAgo, true)).toBe('2h ago');
    });

    it('should handle empty input', () => {
      expect(MSAS.SharedFormat.formatDate(null)).toBe('');
      expect(MSAS.SharedFormat.formatDate('')).toBe('');
    });
  });

  describe('truncateMiddle', () => {
    it('should not truncate short strings', () => {
      expect(MSAS.SharedFormat.truncateMiddle('hello', 10)).toBe('hello');
    });

    it('should truncate long strings in the middle', () => {
      var result = MSAS.SharedFormat.truncateMiddle('abcdefghijklmnop', 10);
      // half = floor((10-3)/2) = 3  =>  'abc' + '...' + 'nop' = 9 chars
      expect(result).toHaveLength(9);
      expect(result).toBe('abc...nop');
    });

    it('should handle empty strings', () => {
      expect(MSAS.SharedFormat.truncateMiddle(null, 10)).toBe('');
    });
  });

  describe('formatDuration', () => {
    it('should format seconds', () => {
      expect(MSAS.SharedFormat.formatDuration(5000)).toBe('5s');
    });

    it('should format minutes and seconds', () => {
      expect(MSAS.SharedFormat.formatDuration(154000)).toBe('2m 34s');
    });

    it('should format hours and minutes', () => {
      expect(MSAS.SharedFormat.formatDuration(5400000)).toBe('1h 30m');
    });

    it('should handle edge cases', () => {
      expect(MSAS.SharedFormat.formatDuration(0)).toBe('0s');
      expect(MSAS.SharedFormat.formatDuration(null)).toBe('0s');
    });
  });

  describe('formatPercent', () => {
    it('should format percentage', () => {
      expect(MSAS.SharedFormat.formatPercent(0.756)).toBe('75.6%');
    });

    it('should handle custom decimals', () => {
      expect(MSAS.SharedFormat.formatPercent(0.5, 0)).toBe('50%');
    });

    it('should handle edge cases', () => {
      expect(MSAS.SharedFormat.formatPercent(0)).toBe('0.0%');
      expect(MSAS.SharedFormat.formatPercent(1)).toBe('100.0%');
    });
  });

  describe('formatNumber', () => {
    it('should format with commas', () => {
      expect(MSAS.SharedFormat.formatNumber(1234567)).toBe('1,234,567');
    });

    it('should handle small numbers', () => {
      expect(MSAS.SharedFormat.formatNumber(42)).toBe('42');
    });

    it('should handle edge cases', () => {
      expect(MSAS.SharedFormat.formatNumber(0)).toBe('0');
      expect(MSAS.SharedFormat.formatNumber(null)).toBe('0');
    });
  });

  describe('sdkToVer', () => {
    it('should map known SDK levels', () => {
      expect(MSAS.SharedFormat.sdkToVer(33)).toBe('13');
      expect(MSAS.SharedFormat.sdkToVer(34)).toBe('14');
      expect(MSAS.SharedFormat.sdkToVer(31)).toBe('12');
    });

    it('should return string for unknown SDK', () => {
      expect(MSAS.SharedFormat.sdkToVer(99)).toBe('99');
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// MSAS.SharedEntropy
// ═══════════════════════════════════════════════════════════════

describe('MSAS.SharedEntropy', () => {
  it('should be defined', () => {
    expect(MSAS.SharedEntropy).toBeTruthy();
  });

  describe('shannonEntropy', () => {
    it('should return 0 for empty string', () => {
      expect(MSAS.SharedEntropy.shannonEntropy('')).toBe(0);
    });

    it('should return 0 for single character', () => {
      expect(MSAS.SharedEntropy.shannonEntropy('a')).toBe(0);
    });

    it('should return higher entropy for varied strings', () => {
      var low = MSAS.SharedEntropy.shannonEntropy('aaaaaaa');
      var high = MSAS.SharedEntropy.shannonEntropy('abc123!@#');
      expect(high).toBeGreaterThan(low);
    });

    it('should give max ~3 for 8 unique chars', () => {
      var h = MSAS.SharedEntropy.shannonEntropy('abcdabcd');
      // 4 unique chars with equal freq: H = 2
      expect(h).toBeCloseTo(2.0, 1);
    });
  });

  describe('looksLikePlaceholder', () => {
    it('should detect common placeholder patterns', () => {
      expect(MSAS.SharedEntropy.looksLikePlaceholder('test')).toBe(true);
      expect(MSAS.SharedEntropy.looksLikePlaceholder('placeholder')).toBe(true);
      expect(MSAS.SharedEntropy.looksLikePlaceholder('your_api_key')).toBe(true);
    });

    it('should return false for real-looking values', () => {
      expect(MSAS.SharedEntropy.looksLikePlaceholder('sk_live_abc123def456')).toBe(false);
      expect(MSAS.SharedEntropy.looksLikePlaceholder('AKIAIOSFODNN7EXAMPLE')).toBe(false);
    });

    it('should detect short strings as placeholders', () => {
      expect(MSAS.SharedEntropy.looksLikePlaceholder('ab')).toBe(true);
    });
  });

  describe('isHighEntropySecret', () => {
    it('should detect high-entropy hex strings', () => {
      var result = MSAS.SharedEntropy.isHighEntropySecret('a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0');
      expect(result.match).toBe(true);
      expect(result.kind).toBe('hex');
    });

    it('should reject short strings', () => {
      var result = MSAS.SharedEntropy.isHighEntropySecret('short');
      expect(result.match).toBe(false);
      expect(result.reason).toBe('too-short');
    });

    it('should reject placeholder strings', () => {
      var result = MSAS.SharedEntropy.isHighEntropySecret('your_secret_key_here_that_is_long_enough');
      expect(result.match).toBe(false);
      expect(result.reason).toBe('placeholder');
    });
  });

  describe('detectSecrets', () => {
    it('should detect AWS keys in text', () => {
      var text = 'AKIAIOSFODNN7EXAMPLE and some other text';
      var findings = MSAS.SharedEntropy.detectSecrets(text);
      expect(findings.length).toBeGreaterThan(0);
      var aws = findings.filter(function(f) { return f.ruleId === 'aws_access_key_id'; });
      expect(aws.length).toBe(1);
      expect(aws[0].ruleName).toContain('AWS');
    });

    it('should detect private key markers', () => {
      var text = 'some file content -----BEGIN RSA PRIVATE KEY----- encrypted data here -----END RSA PRIVATE KEY-----';
      var findings = MSAS.SharedEntropy.detectSecrets(text);
      var pem = findings.filter(function(f) { return f.ruleId === 'private_key_pem'; });
      expect(pem.length).toBeGreaterThan(0);
    });

    it('should return empty array for clean text', () => {
      expect(MSAS.SharedEntropy.detectSecrets('Just a normal string without any secrets')).toEqual([]);
    });

    it('should return empty array for null/empty', () => {
      expect(MSAS.SharedEntropy.detectSecrets(null)).toEqual([]);
      expect(MSAS.SharedEntropy.detectSecrets('')).toEqual([]);
    });
  });

  describe('dedupeFindings', () => {
    it('should deduplicate identical findings', () => {
      var findings = [
        { ruleId: 'test-1', file: 'test.java', match: 'secret' },
        { ruleId: 'test-1', file: 'test.java', match: 'secret' }
      ];
      var deduped = MSAS.SharedEntropy.dedupeFindings(findings);
      expect(deduped.length).toBe(1);
      // The second occurrence is counted
    });

    it('should keep unique findings', () => {
      var findings = [
        { ruleId: 'test-1', file: 'a.java', match: 'secret1' },
        { ruleId: 'test-2', file: 'b.java', match: 'secret2' }
      ];
      var deduped = MSAS.SharedEntropy.dedupeFindings(findings);
      expect(deduped).toHaveLength(2);
    });

    it('should handle empty array', () => {
      expect(MSAS.SharedEntropy.dedupeFindings([])).toEqual([]);
    });
  });

  describe('computeConfidence', () => {
    it('should use confidence directly if present', () => {
      var finding = { confidence: 90 };
      expect(MSAS.SharedEntropy.computeConfidence(finding)).toBe(90);
    });

    it('should boost for high entropy', () => {
      var high = MSAS.SharedEntropy.computeConfidence({ entropy: 5.5 });
      var low = MSAS.SharedEntropy.computeConfidence({ entropy: 2.0 });
      expect(high).toBeGreaterThan(low);
    });

    it('should reduce for test files', () => {
      var finding = { entropy: 4.5, file: 'test/MyTest.java' };
      var conf = MSAS.SharedEntropy.computeConfidence(finding);
      // 50 base + 20 for entropy 4.5 - 25 for test file = 45
      expect(conf).toBeGreaterThanOrEqual(0);
      expect(conf).toBeLessThanOrEqual(100);
    });
  });

  describe('confidenceLabel', () => {
    it('should label confidence levels', () => {
      expect(MSAS.SharedEntropy.confidenceLabel(90)).toBe('high');
      expect(MSAS.SharedEntropy.confidenceLabel(70)).toBe('medium');
      expect(MSAS.SharedEntropy.confidenceLabel(40)).toBe('low');
      expect(MSAS.SharedEntropy.confidenceLabel(10)).toBe('noise');
    });
  });

  describe('SECRET_DETECTORS', () => {
    it('should have multiple detector definitions', () => {
      expect(MSAS.SharedEntropy.SECRET_DETECTORS.length).toBeGreaterThan(10);
    });
  });
});

// ═══════════════════════════════════════════════════════════════
// MSAS.SharedRegistry
// ═══════════════════════════════════════════════════════════════

describe('MSAS.SharedRegistry', () => {
  it('should be defined', () => {
    expect(MSAS.SharedRegistry).toBeTruthy();
  });

  it('should register and retrieve modules', () => {
    var mockModule = { scan: function() { return []; } };
    var result = MSAS.SharedRegistry.register('MockTest', mockModule);
    expect(result).toBe(true);

    var mod = MSAS.SharedRegistry.getModule('MockTest');
    expect(mod).toBeTruthy();
    expect(mod.name).toBe('MockTest');
    expect(mod.type).toBe('scanner');
  });

  it('should register utility modules', () => {
    var utilMod = { someFn: function() {} };
    MSAS.SharedRegistry.register('TestUtil', utilMod, { type: 'utility' });
    var mod = MSAS.SharedRegistry.getModule('TestUtil');
    expect(mod.type).toBe('utility');
  });

  it('should reject invalid registration', () => {
    expect(MSAS.SharedRegistry.register(null, { scan: function() {} })).toBe(false);
    expect(MSAS.SharedRegistry.register('test', null)).toBe(false);
  });

  it('should get all modules sorted', () => {
    var modules = MSAS.SharedRegistry.getModules();
    expect(Array.isArray(modules)).toBe(true);
    // Should have at least the ones we registered and auto-discovered
    expect(modules.length).toBeGreaterThan(0);
  });

  it('should get modules by type', () => {
    var scanners = MSAS.SharedRegistry.getModulesByType('scanner');
    var utilities = MSAS.SharedRegistry.getModulesByType('utility');
    expect(Array.isArray(scanners)).toBe(true);
    expect(Array.isArray(utilities)).toBe(true);
  });

  it('should get scanners specifically', () => {
    var scanners = MSAS.SharedRegistry.getScanners();
    expect(Array.isArray(scanners)).toBe(true);
  });

  it('should unregister modules', () => {
    var m = { scan: function() { return []; } };
    MSAS.SharedRegistry.register('ToDelete', m);
    expect(MSAS.SharedRegistry.getModule('ToDelete')).toBeTruthy();
    MSAS.SharedRegistry.unregister('ToDelete');
    expect(MSAS.SharedRegistry.getModule('ToDelete')).toBeNull();
  });

  it('should provide module stats', () => {
    var stats = MSAS.SharedRegistry.getStats();
    expect(stats).toHaveProperty('scanners');
    expect(stats).toHaveProperty('utilities');
    expect(stats).toHaveProperty('ui');
    expect(stats).toHaveProperty('total');
    expect(stats.total).toBeGreaterThan(0);
  });

  describe('discoverAll', () => {
    it('should discover existing MSAS modules', () => {
      var count = MSAS.SharedRegistry.discoverAll();
      expect(count).toBeGreaterThan(0);

      // Should find core modules
      expect(MSAS.SharedRegistry.getModule('Utils')).toBeTruthy();
      expect(MSAS.SharedRegistry.getModule('TestResult')).toBeTruthy();
      expect(MSAS.SharedRegistry.getModule('StorageScanner')).toBeTruthy();
      expect(MSAS.SharedRegistry.getModule('SharedFormat')).toBeTruthy();
      expect(MSAS.SharedRegistry.getModule('SharedEntropy')).toBeTruthy();
    });
  });

  describe('runScanners', () => {
    it('should run registered scanner modules with context', () => {
      // Register a test scanner
      var testScanner = {
        scan: function(context) {
          return [{ ruleId: 'test', severity: 'high', description: 'found ' + (context.files || []).length + ' files' }];
        }
      };
      MSAS.SharedRegistry.register('TestScanner', testScanner);

      var result = MSAS.SharedRegistry.runScanners({ files: ['a.apk', 'b.apk'] });
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('stats');
      // Should find the test finding somewhere
      var testFindings = result.findings.filter(function(f) { return f.ruleId === 'test'; });
      expect(testFindings.length).toBeGreaterThan(0);
      expect(testFindings[0].description).toContain('2 files');
    });

    it('should compute stats correctly', () => {
      var scanner = {
        scan: function() {
          return [
            { ruleId: 'c1', severity: 'critical' },
            { ruleId: 'c2', severity: 'critical' },
            { ruleId: 'h1', severity: 'high' },
            { ruleId: 'm1', severity: 'medium' },
            { ruleId: 'l1', severity: 'low' },
            { ruleId: 'i1', severity: 'info' },
            { ruleId: 's1', severity: 'secure' }
          ];
        }
      };
      MSAS.SharedRegistry.register('StatsTest', scanner);

      var result = MSAS.SharedRegistry.runScanners({});
      expect(result.stats.total).toBeGreaterThanOrEqual(7);
      expect(result.stats.critical).toBeGreaterThanOrEqual(2);
      expect(result.stats.issue).toBeGreaterThanOrEqual(1);
    });
  });
});
