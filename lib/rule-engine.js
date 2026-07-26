/**
 * mSAS v2 — Declarative Rule Engine (BASE-2)
 *
 * A pure-function rule engine that executes data-defined rules against a context
 * and returns aggregated findings. Integrates with the Rule Editor (UX-4) for
 * runtime enable/disable and profile management.
 *
 * Core concepts:
 *   1. Rules are defined as data objects with a pure scan(context) function
 *   2. The engine orchestrates execution, enabling/disabling, and aggregation
 *   3. Integration with MSAS.RuleEditor for runtime rule management
 *   4. Support for rule categories, severity filtering, and finding deduplication
 *
 * Usage:
 *   // Define a rule
 *   var rule = MSAS.RuleEngine.createRule({
 *     id: 'my-rule-1',
 *     name: 'Check for X',
 *     severity: 'high',
 *     category: 'storage',
 *     scan: function(context) { return [...]; }
 *   });
 *
 *   // Execute all rules
 *   var result = MSAS.RuleEngine.executeAll({ files: [...], strings: [...] });
 *   // result = { findings: [...], stats: { total, critical, high, ... }, duration: 123 }
 *
 *   // Execute specific rules
 *   var result = MSAS.RuleEngine.executeRules(['rule-a', 'rule-b'], context);
 *
 *   // Manage enable/disable (integrates with RuleEditor)
 *   MSAS.RuleEngine.setEnabled('my-rule-1', false);
 *   MSAS.RuleEngine.getEnabledRules(); // only enabled rules
 */

var MSAS = MSAS || {};
MSAS.RuleEngine = (function() {
  'use strict';

  // ── Internal State ──────────────────────────────────────────

  /** Registered rules: { id: ruleDefinition } */
  var _rules = {};

  /** Enabled/disabled state: { id: true/false } */
  var _enabled = {};

  /** Whether to integrate with MSAS.RuleEditor */
  var _integrateWithEditor = true;

  // ── Rule Definition Schema ──────────────────────────────────

  /**
   * Create a rule from a definition object.
   * Validates the schema and returns the rule object.
   *
   * Rule schema:
   * {
   *   id:          string (required)        — Unique identifier
   *   name:        string (required)        — Human-readable name
   *   description: string (optional)        — What the rule checks
   *   severity:    string (required)        — critical | high | medium | low | info | secure
   *   category:    string (optional)        — storage | cryptography | authentication | etc.
   *   cwe:         string (optional)        — CWE identifier (e.g., "CWE-312")
   *   owasp:       string (optional)        — OWASP Mobile Top 10 (e.g., "M2")
   *   masvs:       string (optional)        — MASVS reference (e.g., "MASVS-STORAGE-1")
   *   scan:        function (required)      — Pure function: (context) => findings[]
   *   tags:        Array<string> (optional) — Additional tags for grouping
   * }
   *
   * @param {Object} def - Rule definition
   * @returns {Object|null} The created rule object, or null if invalid
   */
  function createRule(def) {
    if (!def || !def.id || !def.name || typeof def.scan !== 'function') {
      console.warn('[RuleEngine] Invalid rule definition: missing id, name, or scan function');
      return null;
    }

    var rule = {
      id:          def.id,
      name:        def.name,
      description: def.description || '',
      severity:    def.severity || 'medium',
      category:    def.category || 'general',
      cwe:         def.cwe || '',
      owasp:       def.owasp || '',
      masvs:       def.masvs || '',
      tags:        def.tags || [],
      scan:        def.scan,
      builtIn:     def.builtIn !== false,
      source:      def.source || 'rule-engine',
      createdAt:   Date.now()
    };

    _rules[rule.id] = rule;

    // Default to enabled
    if (_enabled[rule.id] === undefined) {
      _enabled[rule.id] = true;
    }

    // Register with RuleEditor if integration is enabled
    if (_integrateWithEditor && typeof MSAS === 'object' && MSAS.RuleEditor) {
      try {
        MSAS.RuleEditor.registerRule(rule);
      } catch (e) {
        // RuleEditor might not be initialized yet — that's fine
      }
    }

    return rule;
  }

  /**
   * Register multiple rules at once.
   * @param {Array} ruleDefs - Array of rule definitions
   * @returns {number} Number of rules successfully created
   */
  function createRules(ruleDefs) {
    if (!ruleDefs || !ruleDefs.length) return 0;
    var count = 0;
    for (var i = 0; i < ruleDefs.length; i++) {
      if (createRule(ruleDefs[i])) count++;
    }
    return count;
  }

  // ── Rule Management ─────────────────────────────────────────

  /**
   * Get a rule by ID.
   * @param {string} id
   * @returns {Object|null}
   */
  function getRule(id) {
    return _rules[id] || null;
  }

  /**
   * Get all registered rules.
   * @returns {Array}
   */
  function getAllRules() {
    var result = [];
    for (var id in _rules) {
      if (_rules.hasOwnProperty(id)) {
        result.push(_rules[id]);
      }
    }
    return result.sort(function(a, b) { return a.id.localeCompare(b.id); });
  }

  /**
   * Get only enabled rules.
   * @returns {Array}
   */
  function getEnabledRules() {
    return getAllRules().filter(function(r) { return _enabled[r.id] !== false; });
  }

  /**
   * Get only disabled rules.
   * @returns {Array}
   */
  function getDisabledRules() {
    return getAllRules().filter(function(r) { return _enabled[r.id] === false; });
  }

  /**
   * Get rules filtered by category.
   * @param {string} category - e.g., 'storage', 'crypto'
   * @returns {Array}
   */
  function getRulesByCategory(category) {
    if (!category) return [];
    return getAllRules().filter(function(r) { return r.category === category; });
  }

  /**
   * Get rules filtered by severity.
   * @param {string} severity - e.g., 'critical', 'high'
   * @returns {Array}
   */
  function getRulesBySeverity(severity) {
    if (!severity) return [];
    return getAllRules().filter(function(r) { return r.severity === severity; });
  }

  // ── Enable/Disable ──────────────────────────────────────────

  /**
   * Enable or disable a rule by ID.
   * Also updates the RuleEditor if integrated.
   * @param {string} id
   * @param {boolean} enabled
   * @returns {boolean} true if updated
   */
  function setEnabled(id, enabled) {
    if (!_rules[id]) return false;
    _enabled[id] = enabled;

    // Sync with RuleEditor
    if (_integrateWithEditor && MSAS.RuleEditor && typeof MSAS.RuleEditor.setRuleEnabled === 'function') {
      try {
        MSAS.RuleEditor.setRuleEnabled(id, enabled);
      } catch (e) { /* ignore */ }
    }
    return true;
  }

  /**
   * Toggle a rule's enabled state.
   * @param {string} id
   * @returns {boolean|null} New state, or null if rule not found
   */
  function toggleEnabled(id) {
    if (!_rules[id]) return null;
    var newState = _enabled[id] === false;
    setEnabled(id, newState);
    return newState;
  }

  /**
   * Enable or disable all rules.
   * @param {boolean} enabled
   */
  function setAllEnabled(enabled) {
    for (var id in _rules) {
      if (_rules.hasOwnProperty(id)) {
        _enabled[id] = enabled;
      }
    }

    if (_integrateWithEditor && MSAS.RuleEditor && typeof MSAS.RuleEditor.setAllRules === 'function') {
      try {
        MSAS.RuleEditor.setAllRules(enabled);
      } catch (e) { /* ignore */ }
    }
  }

  // ── Rule Execution ──────────────────────────────────────────

  /**
   * Execute all enabled rules against the given context.
   *
   * @param {Object} context - The analysis context (files, strings, manifest, etc.)
   * @param {Object} [opts]
   * @param {Array}  [opts.onlyIds]    - Only run these rule IDs
   * @param {boolean} [opts.includeDisabled=false] - Also run disabled rules
   * @param {boolean} [opts.dedupe=true] - Deduplicate findings
   * @returns {{ findings: Array, stats: Object, duration: number }}
   */
  function executeAll(context, opts) {
    opts = opts || {};
    var rulesToRun = opts.onlyIds
      ? getAllRules().filter(function(r) { return opts.onlyIds.indexOf(r.id) >= 0; })
      : (opts.includeDisabled ? getAllRules() : getEnabledRules());

    if (rulesToRun.length === 0) {
      return { findings: [], stats: emptyStats(), duration: 0 };
    }

    var startTime = Date.now();
    var allFindings = [];

    for (var i = 0; i < rulesToRun.length; i++) {
      var rule = rulesToRun[i];
      try {
        var result = rule.scan(context);
        if (result && Array.isArray(result)) {
          for (var j = 0; j < result.length; j++) {
            result[j]._ruleId = rule.id;
            result[j]._ruleName = rule.name;
            // Ensure ruleId is set so dedup works correctly
            if (!result[j].ruleId) result[j].ruleId = rule.id;
          }
          allFindings = allFindings.concat(result);
        }
      } catch (e) {
        console.warn('[RuleEngine] Error executing rule "' + rule.id + '":', e.message);
      }
    }

    // Deduplicate if requested
    if (opts.dedupe !== false && MSAS.SharedEntropy && typeof MSAS.SharedEntropy.dedupeFindings === 'function') {
      allFindings = MSAS.SharedEntropy.dedupeFindings(allFindings);
    }

    var duration = Date.now() - startTime;
    var stats = computeStats(allFindings, rulesToRun.length);

    return { findings: allFindings, stats: stats, duration: duration };
  }

  /**
   * Execute specific rules by ID.
   * @param {Array} ruleIds - Array of rule IDs to execute
   * @param {Object} context - Analysis context
   * @returns {{ findings: Array, stats: Object, duration: number }}
   */
  function executeRules(ruleIds, context) {
    if (!ruleIds || !ruleIds.length) {
      return { findings: [], stats: emptyStats(), duration: 0 };
    }
    return executeAll(context, { onlyIds: ruleIds });
  }

  /**
   * Execute a single rule by ID.
   * @param {string} ruleId
   * @param {Object} context
   * @returns {Array} Findings from the rule
   */
  function executeRule(ruleId, context) {
    var rule = _rules[ruleId];
    if (!rule) return [];
    try {
      var result = rule.scan(context) || [];
      for (var j = 0; j < result.length; j++) {
        result[j]._ruleId = rule.id;
        result[j]._ruleName = rule.name;
      }
      return result;
    } catch (e) {
      console.warn('[RuleEngine] Error executing rule "' + ruleId + '":', e.message);
      return [];
    }
  }

  // ── Stats ───────────────────────────────────────────────────

  /**
   * Compute stats from findings array.
   * @param {Array} findings
   * @param {number} [rulesRun=0]
   * @returns {Object}
   */
  function computeStats(findings, rulesRun) {
    var stats = {
      total: findings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      issue: 0,
      secure: 0,
      rulesRun: rulesRun || 0,
      categories: {}
    };

    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var sev = (f.severity || '').toLowerCase();

      if (sev === 'critical') stats.critical++;
      else if (sev === 'high' || sev === 'issue') stats.high++;
      else if (sev === 'medium') stats.medium++;
      else if (sev === 'low') stats.low++;
      else if (sev === 'info') stats.info++;
      else if (sev === 'secure') stats.secure++;

      // Category breakdown
      var cat = f.category || f._moduleName || 'general';
      stats.categories[cat] = (stats.categories[cat] || 0) + 1;
    }

    return stats;
  }

  function emptyStats() {
    return {
      total: 0, critical: 0, high: 0, medium: 0,
      low: 0, info: 0, secure: 0,
      rulesRun: 0, categories: {}
    };
  }

  // ── Context Construction ────────────────────────────────────

  /**
   * Build a standardized context object from analysis data.
   * This normalizes the various input formats from APK, IPA, and ADB auditors
   * into a consistent context that rules can depend on.
   *
   * @param {Object} data
   * @param {Array}  [data.files]    - File entries from the archive
   * @param {Array}  [data.strings]  - DEX strings array
   * @param {Object} [data.manifest] - Parsed AndroidManifest or Info.plist
   * @param {Object} [data.dex]      - Parsed DEX info (classes, methods, etc.)
   * @param {Object} [data.cert]     - Signing certificate info
   * @param {Array}  [data.findings] - Raw findings from engine
   * @param {string} [data.platform] - 'android' | 'ios'
   * @returns {Object} Normalized context
   */
  function buildContext(data) {
    data = data || {};
    return {
      files:    data.files    || [],
      strings:  data.strings  || [],
      manifest: data.manifest || null,
      dex:      data.dex      || null,
      cert:     data.cert     || null,
      findings: data.findings || [],
      platform: data.platform || 'android',
      appName:  data.appName  || '',
      packageName: data.packageName || '',
      version:  data.version  || '',
      raw:      data          // Original data passthrough
    };
  }

  // ── Integration ─────────────────────────────────────────────

  /**
   * Enable or disable RuleEditor integration.
   * When enabled, all rule operations sync with MSAS.RuleEditor.
   * @param {boolean} enabled
   */
  function setEditorIntegration(enabled) {
    _integrateWithEditor = enabled;
  }

  /**
   * Import rules from the RuleEditor's rule list.
   * This bridges any rules configured in the RuleEditor into the RuleEngine.
   * @returns {number} Number of rules imported
   */
  function importFromRuleEditor() {
    if (typeof MSAS !== 'object' || !MSAS.RuleEditor) return 0;
    try {
      var editorRules = MSAS.RuleEditor.getRules();
      if (!editorRules || !editorRules.length) return 0;
      var count = 0;
      for (var i = 0; i < editorRules.length; i++) {
        var er = editorRules[i];
        if (!_rules[er.id]) {
          // Create a stub rule for editor-only rules (ones without a scan function)
          _rules[er.id] = {
            id: er.id,
            name: er.name,
            description: er.description || '',
            severity: er.severity || 'medium',
            category: er.category || 'general',
            cwe: er.cwe || '',
            owasp: er.owasp || '',
            masvs: er.masvs || '',
            tags: [],
            scan: function() { return []; }, // No-op for editor-only rules
            builtIn: er.builtIn !== false,
            source: 'editor-import',
            createdAt: Date.now()
          };
          _enabled[er.id] = er.enabled !== false;
          count++;
        }
      }
      return count;
    } catch (e) {
      console.warn('[RuleEngine] Error importing from RuleEditor:', e.message);
      return 0;
    }
  }

  // ── Discovery ───────────────────────────────────────────────

  /**
   * Discover and register rules from all registered MSAS scanner modules.
   * Uses the SharedRegistry to find scanner modules and register their scan functions.
   * @returns {number} Number of rules discovered and registered
   */
  function discoverFromRegistry() {
    if (typeof MSAS !== 'object' || !MSAS.SharedRegistry) return 0;
    try {
      // Ensure discovery has been run
      MSAS.SharedRegistry.discoverAll();

      var modules = MSAS.SharedRegistry.getScanners();
      var count = 0;

      for (var i = 0; i < modules.length; i++) {
        var mod = modules[i];
        var ruleId = 'ds-' + mod.name.replace(/([a-z])([A-Z])/g, '$1-$2').toLowerCase();

        // Register the scanner module's scan function as a rule
        if (!_rules[ruleId] && typeof mod.module.scan === 'function') {
          createRule({
            id: ruleId,
            name: mod.name.replace(/([A-Z])/g, ' $1').trim(),
            severity: 'medium',
            category: 'general',
            description: 'Scanner module: ' + mod.name,
            scan: function(context) { return mod.module.scan(context); },
            builtIn: true,
            source: 'scanner-module'
          });
          count++;
        }
      }
      return count;
    } catch (e) {
      console.warn('[RuleEngine] Error discovering from registry:', e.message);
      return 0;
    }
  }

  // ── Reset / Cleanup ─────────────────────────────────────────

  /**
   * Reset the rule engine — clear all rules and enabled states.
   */
  function reset() {
    _rules = {};
    _enabled = {};
  }

  /**
   * Remove a rule by ID.
   * @param {string} id
   * @returns {boolean}
   */
  function removeRule(id) {
    if (!_rules[id]) return false;
    delete _rules[id];
    delete _enabled[id];
    return true;
  }

  // ── Public API ─────────────────────────────────────────────

  return {
    // Rule creation & management
    createRule:           createRule,
    createRules:          createRules,
    getRule:              getRule,
    getAllRules:          getAllRules,
    getEnabledRules:      getEnabledRules,
    getDisabledRules:     getDisabledRules,
    getRulesByCategory:   getRulesByCategory,
    getRulesBySeverity:   getRulesBySeverity,
    removeRule:           removeRule,
    reset:                reset,

    // Enable/disable
    setEnabled:           setEnabled,
    toggleEnabled:        toggleEnabled,
    setAllEnabled:        setAllEnabled,

    // Execution
    executeAll:           executeAll,
    executeRules:         executeRules,
    executeRule:          executeRule,
    buildContext:         buildContext,

    // Integration
    setEditorIntegration: setEditorIntegration,
    importFromRuleEditor: importFromRuleEditor,
    discoverFromRegistry: discoverFromRegistry,

    // Stats
    computeStats:         computeStats
  };
})();
