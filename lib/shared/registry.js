/**
 * mSAS v2 — Module Registry (BASE-1)
 *
 * Central registry for discovering, registering, and accessing all MSAS modules.
 * Provides a unified API to enumerate scanners, get their rules, and run them.
 *
 * Auto-discovers modules registered under the MSAS namespace (MSAS.*Scanner)
 * as well as explicitly registered modules.
 *
 * Usage:
 *   // Auto-discover all MSAS modules
 *   MSAS.SharedRegistry.discoverAll();
 *
 *   // Get all registered modules
 *   var modules = MSAS.SharedRegistry.getModules();
 *
 *   // Get all rules across all modules
 *   var rules = MSAS.SharedRegistry.getRules();
 *
 *   // Run all scanners against context data
 *   var findings = MSAS.SharedRegistry.runScanners({ files: [...], strings: [...] });
 */

var MSAS = MSAS || {};
MSAS.SharedRegistry = (function() {
  'use strict';

  // Registered modules: { name: { module, name, type, rules } }
  var _modules = {};
  var _discovered = false;

  // ── Registration ──────────────────────────────────────────

  /**
   * Register a module with the shared registry.
   * @param {string} name - Module name (e.g., 'StorageScanner')
   * @param {Object} module - The module object (must have a scan function)
   * @param {Object} [opts]
   * @param {string} [opts.type='scanner'] - Module type ('scanner' | 'utility' | 'ui')
   * @param {Array} [opts.rules] - Optional rule definitions from the module
   * @returns {boolean} true if registered successfully
   */
  function register(name, module, opts) {
    if (!name || !module) return false;
    if (typeof module.scan !== 'function' && (!opts || opts.type !== 'utility')) {
      // Warn but still register — some modules are utilities without scan()
      console.warn('[SharedRegistry] Module "' + name + '" has no scan() function');
    }

    var entry = {
      name: name,
      module: module,
      type: (opts && opts.type) || (typeof module.scan === 'function' ? 'scanner' : 'utility'),
      rules: (opts && opts.rules) || (module.rules) || [],
      registeredAt: Date.now()
    };

    _modules[name] = entry;
    return true;
  }

  /**
   * Unregister a module.
   * @param {string} name
   * @returns {boolean}
   */
  function unregister(name) {
    if (!_modules[name]) return false;
    delete _modules[name];
    return true;
  }

  // ── Discovery ─────────────────────────────────────────────

  /**
   * Scanner name suffixes to auto-discover in the MSAS namespace.
   * Any MSAS property ending with these suffixes is treated as a scanner module.
   */
  var SCANNER_SUFFIXES = ['Scanner', 'Engine', 'Analyzer'];

  /**
   * Auto-discover all scanner modules registered in the MSAS namespace.
   * Scans MSAS.* for properties that look like scanner modules.
   * @returns {number} Number of modules discovered
   */
  function discoverAll() {
    var count = 0;
    if (typeof MSAS !== 'object') return 0;

    for (var key in MSAS) {
      if (!MSAS.hasOwnProperty(key)) continue;
      var mod = MSAS[key];
      if (!mod || typeof mod !== 'object') continue;

      // Check if it has a scan() function (scanner module)
      if (typeof mod.scan === 'function') {
        if (!_modules[key]) {
          register(key, mod);
          count++;
        }
      }

      // Also register utility modules that have key APIs
      if (key === 'Utils' || key === 'TestResult' || key === 'StateStore' ||
          key === 'SharedFormat' || key === 'SharedEntropy' || key === 'CVSS') {
        if (!_modules[key]) {
          register(key, mod, { type: 'utility' });
          count++;
        }
      }

      // UI/UX modules
      if (key === 'RuleEditor' || key === 'Dashboard' || key === 'BatchAnalysis' ||
          key === 'ScanHistory' || key === 'Evidence' || key === 'TrendAnalysis' ||
          key === 'RiskMatrix' || key === 'ReportGenerator' || key === 'VirtualScroll') {
        if (!_modules[key]) {
          register(key, mod, { type: 'ui' });
          count++;
        }
      }
    }

    _discovered = true;
    return count;
  }

  // ── Accessors ─────────────────────────────────────────────

  /**
   * Get all registered modules.
   * @returns {Array} Array of { name, module, type, rules }
   */
  function getModules() {
    var result = [];
    for (var name in _modules) {
      if (_modules.hasOwnProperty(name)) {
        result.push(_modules[name]);
      }
    }
    return result.sort(function(a, b) { return a.name.localeCompare(b.name); });
  }

  /**
   * Get a specific module by name.
   * @param {string} name
   * @returns {Object|null} The module entry or null
   */
  function getModule(name) {
    return _modules[name] || null;
  }

  /**
   * Get modules filtered by type.
   * @param {string} type - 'scanner' | 'utility' | 'ui'
   * @returns {Array}
   */
  function getModulesByType(type) {
    return getModules().filter(function(m) { return m.type === type; });
  }

  /**
   * Get all scanner modules (type === 'scanner').
   * @returns {Array}
   */
  function getScanners() {
    return getModulesByType('scanner');
  }

  // ── Rules ─────────────────────────────────────────────────

  /**
   * Collect all rule definitions from registered modules.
   * @returns {Array} Array of rule objects with module info attached
   */
  function getRules() {
    var allRules = [];
    for (var name in _modules) {
      if (!_modules.hasOwnProperty(name)) continue;
      var entry = _modules[name];
      if (entry.rules && entry.rules.length) {
        for (var i = 0; i < entry.rules.length; i++) {
          allRules.push({
            moduleName: name,
            module: entry.module,
            id: entry.rules[i].id || entry.rules[i].ruleId,
            name: entry.rules[i].name || entry.rules[i].ruleName,
            severity: entry.rules[i].severity,
            cwe: entry.rules[i].cwe || '',
            owasp: entry.rules[i].owasp || '',
            masvs: entry.rules[i].masvs || '',
            category: entry.rules[i].category || '',
            description: entry.rules[i].description || ''
          });
        }
      }
    }
    return allRules;
  }

  // ── Execution ─────────────────────────────────────────────

  /**
   * Run all registered scanner modules against the given context.
   * @param {Object} context - Scan context with files, strings, manifest, etc.
   * @param {Object} [opts]
   * @param {Array} [opts.onlyModules] - Only run these module names
   * @param {Array} [opts.excludeModules] - Skip these module names
   * @returns {{ findings: Array, stats: Object }}
   */
  function runScanners(context, opts) {
    context = context || {};
    opts = opts || {};
    var allFindings = [];
    var modules = getScanners();

    for (var i = 0; i < modules.length; i++) {
      var mod = modules[i];

      // Filtering
      if (opts.onlyModules && opts.onlyModules.indexOf(mod.name) === -1) continue;
      if (opts.excludeModules && opts.excludeModules.indexOf(mod.name) !== -1) continue;

      try {
        var result = mod.module.scan(context);
        if (result && Array.isArray(result)) {
          // Tag each finding with its source module
          for (var j = 0; j < result.length; j++) {
            result[j]._moduleName = mod.name;
          }
          allFindings = allFindings.concat(result);
        }
      } catch (e) {
        console.warn('[SharedRegistry] Error running module "' + mod.name + '":', e.message);
      }
    }

    // Compute stats
    var stats = {
      total: allFindings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
      issue: 0,
      secure: 0,
      modulesRun: modules.length
    };

    for (var k = 0; k < allFindings.length; k++) {
      var sev = allFindings[k].severity;
      if (sev === 'critical') stats.critical++;
      else if (sev === 'high' || sev === 'issue') { stats.high++; stats.issue++; }
      else if (sev === 'medium') stats.medium++;
      else if (sev === 'low') stats.low++;
      else if (sev === 'info') stats.info++;
      else if (sev === 'secure') stats.secure++;
    }

    return { findings: allFindings, stats: stats };
  }

  /**
   * Run a specific module by name against context.
   * @param {string} name - Module name
   * @param {Object} context - Scan context
   * @returns {Array} Findings array from the module
   */
  function runModule(name, context) {
    var mod = _modules[name];
    if (!mod || typeof mod.module.scan !== 'function') return [];
    try {
      return mod.module.scan(context) || [];
    } catch (e) {
      console.warn('[SharedRegistry] Error running module "' + name + '":', e.message);
      return [];
    }
  }

  /**
   * Check if discovery has been run.
   * @returns {boolean}
   */
  function isDiscovered() {
    return _discovered;
  }

  /**
   * Get a count of registered modules.
   * @returns {{ scanners: number, utilities: number, ui: number, total: number }}
   */
  function getStats() {
    var scanners = 0, utilities = 0, ui = 0;
    for (var name in _modules) {
      if (!_modules.hasOwnProperty(name)) continue;
      if (_modules[name].type === 'scanner') scanners++;
      else if (_modules[name].type === 'utility') utilities++;
      else if (_modules[name].type === 'ui') ui++;
    }
    return { scanners: scanners, utilities: utilities, ui: ui, total: scanners + utilities + ui };
  }

  // ── Public API ─────────────────────────────────────────────

  return {
    register:       register,
    unregister:     unregister,
    discoverAll:    discoverAll,
    getModules:     getModules,
    getModule:      getModule,
    getModulesByType: getModulesByType,
    getScanners:    getScanners,
    getRules:       getRules,
    runScanners:    runScanners,
    runModule:      runModule,
    isDiscovered:   isDiscovered,
    getStats:       getStats
  };
})();
