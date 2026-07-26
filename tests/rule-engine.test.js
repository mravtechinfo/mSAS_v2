/**
 * mSAS v2 — Unit Tests: Declarative Rule Engine (BASE-2)
 *
 * Tests for MSAS.RuleEngine — rule creation, execution, enable/disable,
 * findings aggregation, and integration with RuleEditor.
 */

import { describe, it, expect, beforeEach } from 'vitest';

describe('MSAS.RuleEngine', () => {
  beforeEach(() => {
    // Reset the rule engine for clean test state
    MSAS.RuleEngine.reset();
  });

  it('should be defined', () => {
    expect(MSAS.RuleEngine).toBeTruthy();
  });

  // ═══════════════════════════════════════════════════════════
  // Rule Creation
  // ═══════════════════════════════════════════════════════════

  describe('createRule', () => {
    it('should create a valid rule', () => {
      var rule = MSAS.RuleEngine.createRule({
        id: 'test-rule-1',
        name: 'Test Rule',
        severity: 'high',
        category: 'storage',
        cwe: 'CWE-312',
        owasp: 'M2',
        masvs: 'MASVS-STORAGE-1',
        description: 'A test rule for unit testing',
        scan: function() { return []; }
      });

      expect(rule).toBeTruthy();
      expect(rule.id).toBe('test-rule-1');
      expect(rule.name).toBe('Test Rule');
      expect(rule.severity).toBe('high');
      expect(rule.category).toBe('storage');
      expect(rule.cwe).toBe('CWE-312');
      expect(rule.builtIn).toBe(true);
    });

    it('should reject invalid rules', () => {
      expect(MSAS.RuleEngine.createRule({})).toBeNull();
      expect(MSAS.RuleEngine.createRule(null)).toBeNull();
      expect(MSAS.RuleEngine.createRule({ id: 'x', name: 'y' })).toBeNull(); // no scan fn
    });

    it('should set sensible defaults', () => {
      var rule = MSAS.RuleEngine.createRule({
        id: 'test-defaults',
        name: 'Defaults',
        scan: function() { return []; }
      });
      expect(rule.severity).toBe('medium');
      expect(rule.category).toBe('general');
      expect(rule.cwe).toBe('');
      expect(rule.description).toBe('');
    });
  });

  describe('createRules', () => {
    it('should create multiple rules at once', () => {
      var count = MSAS.RuleEngine.createRules([
        { id: 'multi-1', name: 'Rule 1', scan: function() { return []; } },
        { id: 'multi-2', name: 'Rule 2', scan: function() { return []; } },
        { id: 'multi-3', name: 'Rule 3', scan: function() { return []; } }
      ]);
      expect(count).toBe(3);
      expect(MSAS.RuleEngine.getRule('multi-1')).toBeTruthy();
      expect(MSAS.RuleEngine.getRule('multi-2')).toBeTruthy();
      expect(MSAS.RuleEngine.getRule('multi-3')).toBeTruthy();
    });

    it('should handle empty input', () => {
      expect(MSAS.RuleEngine.createRules([])).toBe(0);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Rule Management
  // ═══════════════════════════════════════════════════════════

  describe('getAllRules', () => {
    it('should return all registered rules', () => {
      MSAS.RuleEngine.createRules([
        { id: 'a', name: 'A', scan: function() { return []; } },
        { id: 'b', name: 'B', scan: function() { return []; } }
      ]);
      var rules = MSAS.RuleEngine.getAllRules();
      expect(rules).toHaveLength(2);
    });

    it('should return empty array when no rules', () => {
      expect(MSAS.RuleEngine.getAllRules()).toEqual([]);
    });
  });

  describe('getRulesByCategory', () => {
    it('should filter rules by category', () => {
      MSAS.RuleEngine.createRules([
        { id: 'cat-1', name: 'S1', category: 'storage', scan: function() { return []; } },
        { id: 'cat-2', name: 'C1', category: 'cryptography', scan: function() { return []; } },
        { id: 'cat-3', name: 'S2', category: 'storage', scan: function() { return []; } }
      ]);
      var storage = MSAS.RuleEngine.getRulesByCategory('storage');
      expect(storage).toHaveLength(2);
    });
  });

  describe('getRulesBySeverity', () => {
    it('should filter rules by severity', () => {
      MSAS.RuleEngine.createRules([
        { id: 'sev-1', name: 'Critical', severity: 'critical', scan: function() { return []; } },
        { id: 'sev-2', name: 'High', severity: 'high', scan: function() { return []; } },
        { id: 'sev-3', name: 'Info', severity: 'info', scan: function() { return []; } }
      ]);
      var crit = MSAS.RuleEngine.getRulesBySeverity('critical');
      expect(crit).toHaveLength(1);
      expect(crit[0].id).toBe('sev-1');
    });
  });

  describe('removeRule', () => {
    it('should remove a rule by ID', () => {
      MSAS.RuleEngine.createRule({ id: 'removable', name: 'Remove Me', scan: function() { return []; } });
      expect(MSAS.RuleEngine.getRule('removable')).toBeTruthy();
      expect(MSAS.RuleEngine.removeRule('removable')).toBe(true);
      expect(MSAS.RuleEngine.getRule('removable')).toBeNull();
    });

    it('should return false for non-existent rule', () => {
      expect(MSAS.RuleEngine.removeRule('nonexistent')).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Enable/Disable
  // ═══════════════════════════════════════════════════════════

  describe('setEnabled / toggleEnabled', () => {
    it('should enable and disable rules', () => {
      MSAS.RuleEngine.createRule({ id: 'toggle-me', name: 'Toggle', scan: function() { return []; } });
      expect(MSAS.RuleEngine.getEnabledRules()).toHaveLength(1);

      MSAS.RuleEngine.setEnabled('toggle-me', false);
      expect(MSAS.RuleEngine.getEnabledRules()).toHaveLength(0);
      expect(MSAS.RuleEngine.getDisabledRules()).toHaveLength(1);

      MSAS.RuleEngine.setEnabled('toggle-me', true);
      expect(MSAS.RuleEngine.getEnabledRules()).toHaveLength(1);
    });

    it('should toggle states', () => {
      MSAS.RuleEngine.createRule({ id: 'tog', name: 'Tog', scan: function() { return []; } });
      expect(MSAS.RuleEngine.toggleEnabled('tog')).toBe(false);
      expect(MSAS.RuleEngine.toggleEnabled('tog')).toBe(true);
    });

    it('should return false for invalid rule', () => {
      expect(MSAS.RuleEngine.setEnabled('does-not-exist', false)).toBe(false);
    });

    it('should return null for toggling non-existent rule', () => {
      expect(MSAS.RuleEngine.toggleEnabled('does-not-exist')).toBeNull();
    });
  });

  describe('setAllEnabled', () => {
    it('should toggle all rules', () => {
      MSAS.RuleEngine.createRules([
        { id: 'all-1', name: 'A', scan: function() { return []; } },
        { id: 'all-2', name: 'B', scan: function() { return []; } }
      ]);
      MSAS.RuleEngine.setAllEnabled(false);
      expect(MSAS.RuleEngine.getEnabledRules()).toHaveLength(0);

      MSAS.RuleEngine.setAllEnabled(true);
      expect(MSAS.RuleEngine.getEnabledRules()).toHaveLength(2);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Rule Execution
  // ═══════════════════════════════════════════════════════════

  describe('executeAll', () => {
    it('should execute all enabled rules against context', () => {
      MSAS.RuleEngine.createRule({
        id: 'exec-1',
        name: 'Files Check',
        category: 'storage',
        severity: 'high',
        scan: function(context) {
          return context.files && context.files.length > 0
            ? [{ ruleId: 'exec-1', severity: 'high', description: 'Files found: ' + context.files.length }]
            : [];
        }
      });

      var result = MSAS.RuleEngine.executeAll({ files: ['a.apk', 'b.apk'] });
      expect(result).toHaveProperty('findings');
      expect(result).toHaveProperty('stats');
      expect(result).toHaveProperty('duration');
      expect(typeof result.duration).toBe('number');
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].description).toBe('Files found: 2');
    });

    it('should not execute disabled rules', () => {
      MSAS.RuleEngine.createRule({
        id: 'disabled-rule',
        name: 'Disabled',
        scan: function() { return [{ id: 'should-not-appear' }]; }
      });
      MSAS.RuleEngine.setEnabled('disabled-rule', false);

      var result = MSAS.RuleEngine.executeAll({});
      expect(result.findings).toHaveLength(0);
    });

    it('should execute disabled rules when includeDisabled=true', () => {
      MSAS.RuleEngine.createRule({
        id: 'disabled-but-included',
        name: 'Included',
        scan: function() { return [{ finding: 'yes' }]; }
      });
      MSAS.RuleEngine.setEnabled('disabled-but-included', false);

      var result = MSAS.RuleEngine.executeAll({}, { includeDisabled: true });
      expect(result.findings).toHaveLength(1);
    });

    it('should execute specific rules with onlyIds', () => {
      MSAS.RuleEngine.createRules([
        { id: 'specific-1', name: 'S1', scan: function() { return [{ id: 'f1' }]; } },
        { id: 'specific-2', name: 'S2', scan: function() { return [{ id: 'f2' }]; } }
      ]);

      var result = MSAS.RuleEngine.executeAll({}, { onlyIds: ['specific-1'] });
      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].id).toBe('f1');
    });

    it('should handle rules with errors gracefully', () => {
      MSAS.RuleEngine.createRule({
        id: 'error-rule',
        name: 'Error',
        scan: function() { throw new Error('Test error'); }
      });

      // Should not throw
      var result = MSAS.RuleEngine.executeAll({});
      expect(result.findings).toHaveLength(0);
    });

    it('should tag findings with rule metadata', () => {
      MSAS.RuleEngine.createRule({
        id: 'tag-test',
        name: 'Tag Test Rule',
        scan: function() { return [{ finding: 'hello' }]; }
      });

      var result = MSAS.RuleEngine.executeAll({});
      expect(result.findings[0]._ruleId).toBe('tag-test');
      expect(result.findings[0]._ruleName).toBe('Tag Test Rule');
    });
  });

  describe('executeRules', () => {
    it('should execute specific rules by ID array', () => {
      MSAS.RuleEngine.createRules([
        { id: 'er-1', name: 'ER1', scan: function() { return [{ id: 'a' }]; } },
        { id: 'er-2', name: 'ER2', scan: function() { return [{ id: 'b' }]; } },
        { id: 'er-3', name: 'ER3', scan: function() { return [{ id: 'c' }]; } }
      ]);

      var result = MSAS.RuleEngine.executeRules(['er-1', 'er-3'], {});
      expect(result.findings).toHaveLength(2);
      expect(result.findings[0].id).toBe('a');
      expect(result.findings[1].id).toBe('c');
    });

    it('should handle empty ID array', () => {
      var result = MSAS.RuleEngine.executeRules([], {});
      expect(result.findings).toHaveLength(0);
    });
  });

  describe('executeRule', () => {
    it('should execute a single rule', () => {
      MSAS.RuleEngine.createRule({
        id: 'single-exec',
        name: 'Single',
        scan: function() { return [{ finding: 'single result' }]; }
      });

      var findings = MSAS.RuleEngine.executeRule('single-exec', {});
      expect(findings).toHaveLength(1);
      expect(findings[0]._ruleId).toBe('single-exec');
    });

    it('should return empty for non-existent rule', () => {
      var findings = MSAS.RuleEngine.executeRule('does-not-exist', {});
      expect(findings).toEqual([]);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // buildContext
  // ═══════════════════════════════════════════════════════════

  describe('buildContext', () => {
    it('should build a standardized context', () => {
      var ctx = MSAS.RuleEngine.buildContext({
        files: ['test.apk'],
        strings: ['hello', 'world'],
        manifest: { package: 'com.test' },
        platform: 'android'
      });

      expect(ctx.files).toEqual(['test.apk']);
      expect(ctx.strings).toEqual(['hello', 'world']);
      expect(ctx.manifest.package).toBe('com.test');
      expect(ctx.platform).toBe('android');
    });

    it('should provide defaults for missing fields', () => {
      var ctx = MSAS.RuleEngine.buildContext({});
      expect(ctx.files).toEqual([]);
      expect(ctx.strings).toEqual([]);
      expect(ctx.manifest).toBeNull();
      expect(ctx.platform).toBe('android');
    });

    it('should include raw data passthrough', () => {
      var raw = { customField: 'custom value' };
      var ctx = MSAS.RuleEngine.buildContext(raw);
      expect(ctx.raw.customField).toBe('custom value');
    });
  });

  // ═══════════════════════════════════════════════════════════
  // computeStats
  // ═══════════════════════════════════════════════════════════

  describe('computeStats', () => {
    it('should compute correct severity counts', () => {
      var findings = [
        { severity: 'critical' },
        { severity: 'critical' },
        { severity: 'high' },
        { severity: 'medium' },
        { severity: 'low' },
        { severity: 'info' },
        { severity: 'secure' }
      ];

      var stats = MSAS.RuleEngine.computeStats(findings, 10);
      expect(stats.total).toBe(7);
      expect(stats.critical).toBe(2);
      expect(stats.high).toBe(1);
      expect(stats.medium).toBe(1);
      expect(stats.low).toBe(1);
      expect(stats.info).toBe(1);
      expect(stats.secure).toBe(1);
      expect(stats.rulesRun).toBe(10);
    });

    it('should compute category breakdown', () => {
      var findings = [
        { severity: 'high', category: 'storage' },
        { severity: 'critical', category: 'crypto' },
        { severity: 'medium', category: 'storage' }
      ];

      var stats = MSAS.RuleEngine.computeStats(findings);
      expect(stats.categories.storage).toBe(2);
      expect(stats.categories.crypto).toBe(1);
    });

    it('should handle empty findings', () => {
      var stats = MSAS.RuleEngine.computeStats([]);
      expect(stats.total).toBe(0);
      expect(stats.critical).toBe(0);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Integration
  // ═══════════════════════════════════════════════════════════

  describe('integration with RuleEditor', () => {
    it('should register rules with RuleEditor automatically', () => {
      // Reset rule editor too
      MSAS.RuleEditor.init();

      var ruleCount = MSAS.RuleEditor.getRules().length;

      MSAS.RuleEngine.createRule({
        id: 'editor-sync',
        name: 'Editor Sync',
        severity: 'high',
        category: 'network',
        cwe: 'CWE-319',
        scan: function() { return []; }
      });

      // After creating a rule in the engine, it should also be in the editor
      var editorRule = MSAS.RuleEditor.getRules().filter(function(r) { return r.id === 'editor-sync'; });
      expect(editorRule.length).toBe(1);
      expect(editorRule[0].name).toBe('Editor Sync');
    });

    it('should sync enable/disable with RuleEditor', () => {
      MSAS.RuleEngine.reset();
      MSAS.RuleEditor.init();

      MSAS.RuleEngine.createRule({
        id: 'sync-enabled',
        name: 'Sync Test',
        scan: function() { return []; }
      });

      expect(MSAS.RuleEditor.getRules().filter(function(r) { return r.id === 'sync-enabled'; })[0].enabled).toBe(true);

      MSAS.RuleEngine.setEnabled('sync-enabled', false);
      expect(MSAS.RuleEditor.getRules().filter(function(r) { return r.id === 'sync-enabled'; })[0].enabled).toBe(false);
    });
  });

  describe('discoverFromRegistry', () => {
    it('should discover and register scanner modules', () => {
      MSAS.RuleEngine.reset();

      // Make sure registry has discovered modules
      if (MSAS.SharedRegistry) {
        MSAS.SharedRegistry.discoverAll();

        var count = MSAS.RuleEngine.discoverFromRegistry();
        expect(count).toBeGreaterThan(0);

        // Should have registered some rules
        var rules = MSAS.RuleEngine.getAllRules();
        expect(rules.length).toBeGreaterThan(0);
      }
    });
  });

  describe('setEditorIntegration', () => {
    it('should toggle RuleEditor integration', () => {
      // Should not throw
      MSAS.RuleEngine.setEditorIntegration(false);
      MSAS.RuleEngine.setEditorIntegration(true);
    });
  });
});
