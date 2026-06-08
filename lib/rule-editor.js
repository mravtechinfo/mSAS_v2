/**
 * mSAS v2 — Rule Editor GUI
 * 
 * Enable/disable/prioritize rules. Create custom rules. Save/load profiles.
 * Part of Phase 8: UX Polish (UX-4).
 */

var MSAS = MSAS || {};

MSAS.RuleEditor = (function() {
  'use strict';

  var STORAGE_KEY = 'msas-rule-profiles';
  var rules = [];
  var enabledRules = {};
  var customRules = [];
  var currentProfile = 'default';
  var profiles = {};

  // ── Rule Discovery ─────────────────────────────────────────

  var knownRules = [
    // Storage
    { id: 'mastg-storage-1-sqlite', name: 'SQLite Database Storage', severity: 'high', description: 'SQLite databases stored unencrypted. Use encrypted storage.', cwe: 'CWE-312', owasp: 'M2', masvs: 'MASVS-STORAGE-1', category: 'storage' },
    { id: 'mastg-storage-2-shared-prefs', name: 'SharedPreferences Audit', severity: 'medium', description: 'Check for MODE_WORLD_READABLE/WRITABLE and plaintext sensitive data.', cwe: 'CWE-276', owasp: 'M2', masvs: 'MASVS-STORAGE-1', category: 'storage' },
    { id: 'mastg-storage-3-log-leakage', name: 'Log Statement Leakage', severity: 'medium', description: 'Log statements may leak sensitive information.', cwe: 'CWE-532', owasp: 'M2', masvs: 'MASVS-STORAGE-2', category: 'storage' },
    { id: 'mastg-storage-4-firebase', name: 'Firebase Database Detection', severity: 'critical', description: 'Firebase databases must have proper security rules.', cwe: 'CWE-284', owasp: 'M2', masvs: 'MASVS-STORAGE-1', category: 'storage' },
    { id: 'mastg-storage-5-clipboard', name: 'Clipboard Misuse', severity: 'medium', description: 'Clipboard usage for sensitive data.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-3', category: 'storage' },
    { id: 'mastg-storage-6-screenshot', name: 'Screenshot Prevention', severity: 'medium', description: 'FLAG_SECURE not set on sensitive windows.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-4', category: 'storage' },
    { id: 'mastg-storage-7-keystore', name: 'KeyStore/Keychain Analysis', severity: 'critical', description: 'Verify proper KeyStore usage.', cwe: 'CWE-320', owasp: 'M5', masvs: 'MASVS-STORAGE-5', category: 'storage' },
    { id: 'mastg-storage-8-notifications', name: 'Notification Data Leakage', severity: 'medium', description: 'Sensitive data in push notification payloads.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-8', category: 'storage' },
    { id: 'mastg-storage-9-analytics', name: 'Analytics SDK Data Leakage', severity: 'medium', description: 'PII sent to analytics SDKs.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-9', category: 'storage' },
    { id: 'mastg-storage-10-device-access', name: 'Device Access Controls', severity: 'medium', description: 'Verify screen lock, device admin, root detection.', cwe: 'CWE-287', owasp: 'M2', masvs: 'MASVS-STORAGE-10', category: 'storage' },
    { id: 'mastg-storage-11-cache', name: 'Cache & Temp File Analysis', severity: 'medium', description: 'Sensitive data in caches.', cwe: 'CWE-312', owasp: 'M2', masvs: 'MASVS-STORAGE-6', category: 'storage' },
    { id: 'mastg-storage-12-backup', name: 'Backup Vulnerability', severity: 'high', description: 'Backup enabled allows data extraction.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-7', category: 'storage' },
    { id: 'mastg-storage-13-scoped', name: 'Scoped Storage Compliance', severity: 'medium', description: 'Legacy external storage access.', cwe: 'CWE-200', owasp: 'M2', masvs: 'MASVS-STORAGE-1', category: 'storage' },
    // Crypto
    { id: 'mastg-crypto-1-weak-ciphers', name: 'Weak Cipher Detection', severity: 'critical', description: 'AES-ECB, DES, RC4, MD5 detection.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-1', category: 'cryptography' },
    { id: 'mastg-crypto-2-cert-validation', name: 'Certificate Validation', severity: 'critical', description: 'Custom TrustManager, X509TrustManager overrides.', cwe: 'CWE-295', owasp: 'M3', masvs: 'MASVS-CRYPTO-2', category: 'cryptography' },
    { id: 'mastg-crypto-3-hardcoded-keys', name: 'Hardcoded Keys', severity: 'critical', description: 'Hardcoded AES/RSA keys detected.', cwe: 'CWE-321', owasp: 'M5', masvs: 'MASVS-CRYPTO-3', category: 'cryptography' },
    { id: 'mastg-crypto-4-custom-crypto', name: 'Custom Cryptography', severity: 'high', description: 'Custom algorithms detected.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-4', category: 'cryptography' },
    { id: 'mastg-crypto-5-rng', name: 'Random Number Generator', severity: 'medium', description: 'Predictable RNG used.', cwe: 'CWE-330', owasp: 'M5', masvs: 'MASVS-CRYPTO-5', category: 'cryptography' },
    { id: 'mastg-crypto-6-pinning', name: 'Certificate Pinning', severity: 'high', description: 'Network security config pin-set.', cwe: 'CWE-295', owasp: 'M3', masvs: 'MASVS-NETWORK-4', category: 'cryptography' },
    // Auth
    { id: 'mastg-auth-1-password-policy', name: 'Password Policy Analysis', severity: 'high', description: 'Extract and verify password policy.', cwe: 'CWE-521', owasp: 'M4', masvs: 'MASVS-AUTH-1', category: 'authentication' },
    { id: 'mastg-auth-3-session', name: 'Session Management', severity: 'critical', description: 'Session token handling and timeout.', cwe: 'CWE-613', owasp: 'M6', masvs: 'MASVS-AUTH-3', category: 'authentication' },
    { id: 'mastg-auth-4-oauth', name: 'OAuth 2.0 / PKCE', severity: 'high', description: 'OAuth flow and PKCE verification.', cwe: 'CWE-862', owasp: 'M4', masvs: 'MASVS-AUTH-5', category: 'authentication' },
    { id: 'mastg-auth-5-bypass', name: 'Local Auth Bypass', severity: 'high', description: 'Authentication bypass detection.', cwe: 'CWE-287', owasp: 'M4', masvs: 'MASVS-AUTH-8', category: 'authentication' },
    // Network
    { id: 'mastg-network-1-cleartext', name: 'Cleartext Traffic', severity: 'high', description: 'HTTP traffic interception risk.', cwe: 'CWE-319', owasp: 'M3', masvs: 'MASVS-NETWORK-1', category: 'network' },
    { id: 'mastg-network-2-tls', name: 'TLS Configuration', severity: 'critical', description: 'TLS 1.2+ compliance.', cwe: 'CWE-326', owasp: 'M3', masvs: 'MASVS-NETWORK-2', category: 'network' },
    { id: 'mastg-network-3-hostname', name: 'Hostname Verification', severity: 'critical', description: 'ALLOW_ALL_HOSTNAME_VERIFIER check.', cwe: 'CWE-295', owasp: 'M3', masvs: 'MASVS-NETWORK-3', category: 'network' },
    { id: 'mastg-network-4-websocket', name: 'WebSocket Security', severity: 'high', description: 'Insecure WebSocket connections.', cwe: 'CWE-319', owasp: 'M3', masvs: 'MASVS-NETWORK-1', category: 'network' },
    { id: 'mastg-network-5-sdk', name: '3rd-Party Network SDK', severity: 'high', description: 'Network SDK security audit.', cwe: 'CWE-1104', owasp: 'M3', masvs: 'MASVS-NETWORK-5', category: 'network' },
    { id: 'mastg-network-6-ats', name: 'iOS ATS Analysis', severity: 'high', description: 'App Transport Security configuration.', cwe: 'CWE-319', owasp: 'M3', masvs: 'MASVS-NETWORK-1', category: 'network' },
    // Platform
    { id: 'mastg-platform-1-webview', name: 'WebView Security', severity: 'critical', description: 'JavaScript enabled, file access, JSI.', cwe: 'CWE-749', owasp: 'M1', masvs: 'MASVS-PLATFORM-1', category: 'platform' },
    { id: 'mastg-platform-2-deeplinks', name: 'Deep Link Validation', severity: 'high', description: 'URL scheme hijacking risk.', cwe: 'CWE-939', owasp: 'M1', masvs: 'MASVS-PLATFORM-3', category: 'platform' },
    { id: 'mastg-platform-3-tapjacking', name: 'Tapjacking Detection', severity: 'high', description: 'Overlay and tapjacking risk.', cwe: 'CWE-1021', owasp: 'M1', masvs: 'MASVS-PLATFORM-9', category: 'platform' },
    { id: 'mastg-platform-4-pendingintent', name: 'PendingIntent Security', severity: 'high', description: 'Mutable PendingIntent detected.', cwe: 'CWE-287', owasp: 'M1', masvs: 'MASVS-PLATFORM-8', category: 'platform' },
    { id: 'mastg-platform-5-provider', name: 'Content Provider Security', severity: 'high', description: 'SQL injection in content providers.', cwe: 'CWE-89', owasp: 'M1', masvs: 'MASVS-PLATFORM-4', category: 'platform' },
    { id: 'mastg-platform-6-components', name: 'Service & Broadcast Receiver', severity: 'high', description: 'Exported components without permission.', cwe: 'CWE-926', owasp: 'M1', masvs: 'MASVS-PLATFORM-5', category: 'platform' },
    { id: 'mastg-platform-7-task-affinity', name: 'Task Affinity Hijacking', severity: 'high', description: 'StrandHogg vulnerability.', cwe: 'CWE-287', owasp: 'M1', masvs: 'MASVS-PLATFORM-5', category: 'platform' },
    // Code
    { id: 'mastg-code-1-proguard', name: 'ProGuard/R8 Effectiveness', severity: 'high', description: 'Code obfuscation analysis.', cwe: 'CWE-656', owasp: 'M9', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'mastg-code-2-debug-symbols', name: 'Debug Symbols Check', severity: 'medium', description: 'Debug symbols in release builds.', cwe: 'CWE-200', owasp: 'M9', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'mastg-code-4-deserialization', name: 'Deserialization Vulnerability', severity: 'critical', description: 'Unsafe deserialization.', cwe: 'CWE-502', owasp: 'M8', masvs: 'MASVS-CODE-7', category: 'code_quality' },
    { id: 'mastg-code-5-update', name: 'Insecure Update Mechanism', severity: 'high', description: 'Unverified update URLs.', cwe: 'CWE-494', owasp: 'M8', masvs: 'MASVS-CODE-8', category: 'code_quality' },
    { id: 'mastg-code-6-ndk', name: 'Native Code (JNI/NDK)', severity: 'critical', description: 'JNI and native code vulnerabilities.', cwe: 'CWE-120', owasp: 'M8', masvs: 'MASVS-CODE-4', category: 'code_quality' },
    { id: 'mastg-code-8-permissions', name: 'Permission Over-Provisioning', severity: 'high', description: 'Unused dangerous permissions.', cwe: 'CWE-272', owasp: 'M1', masvs: 'MASVS-CODE-6', category: 'code_quality' },
    { id: 'mastg-code-9-perm-combos', name: 'Dangerous Permission Combos', severity: 'medium', description: 'CAMERA+MIC, LOCATION+INTERNET combos.', cwe: 'CWE-272', owasp: 'M1', masvs: 'MASVS-CODE-6', category: 'code_quality' },
    { id: 'mastg-code-10-alarms', name: 'Exact Alarm & Background', severity: 'low', description: 'SCHEDULE_EXACT_ALARM usage.', cwe: 'CWE-200', owasp: 'M9', masvs: 'MASVS-CODE-9', category: 'code_quality' },
    // Resilience
    { id: 'mastg-resilience-1-root', name: 'Root/Jailbreak Detection', severity: 'high', description: 'Root detection bypass checks.', cwe: 'CWE-693', owasp: 'M8', masvs: 'MASVS-RESILIENCE-1', category: 'resilience' },
    { id: 'mastg-resilience-2-anti-debug', name: 'Anti-Debugging', severity: 'medium', description: 'Debugger detection mechanisms.', cwe: 'CWE-693', owasp: 'M8', masvs: 'MASVS-RESILIENCE-2', category: 'resilience' },
    { id: 'mastg-resilience-3-integrity', name: 'Runtime Integrity', severity: 'high', description: 'Signature and integrity verification.', cwe: 'CWE-353', owasp: 'M8', masvs: 'MASVS-RESILIENCE-3', category: 'resilience' },
    { id: 'mastg-resilience-4-re-tools', name: 'RE Tool Detection', severity: 'medium', description: 'Frida, Xposed, Magisk detection.', cwe: 'CWE-693', owasp: 'M8', masvs: 'MASVS-RESILIENCE-4', category: 'resilience' },
    // AI
    { id: 'mastg-ai-1-models', name: 'On-Device Model Extraction', severity: 'high', description: 'Unprotected ML models.', cwe: 'CWE-312', owasp: 'M2', masvs: 'AI-ANDROID-1', category: 'ai_ml' },
    { id: 'mastg-ai-2-api-keys', name: 'Hardcoded AI API Keys', severity: 'critical', description: 'OpenAI, Anthropic, Gemini keys.', cwe: 'CWE-798', owasp: 'M9', masvs: 'AI-ANDROID-2', category: 'ai_ml' },
    { id: 'mastg-ai-5-sdks', name: 'AI SDK Data Collection', severity: 'high', description: 'Firebase ML Kit, CoreML telemetry.', cwe: 'CWE-200', owasp: 'M2', masvs: 'AI-ANDROID-5', category: 'ai_ml' },
    { id: 'mastg-ai-10-rag', name: 'RAG / Vector DB Audit', severity: 'critical', description: 'Exposed vector databases.', cwe: 'CWE-200', owasp: 'M2', masvs: 'AI-ANDROID-10', category: 'ai_ml' },
    // Engine rules
    { id: 'debug_cert', name: 'Debug Certificate Used', severity: 'high', description: 'APK signed with Android debug key. Debug builds must not be distributed.', cwe: 'CWE-321', owasp: 'M9', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'v1_only_sig', name: 'v1 (JAR) Signature Only', severity: 'medium', description: 'v1 signing vulnerable to Janus exploit.', cwe: 'CWE-326', owasp: 'M3', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'obfuscated', name: 'Code Obfuscation Active', severity: 'info', description: 'ProGuard/R8 obfuscation detected.', cwe: '', owasp: '', masvs: 'MASVS-RESILIENCE-9', category: 'code_quality' },
    { id: 'expired_cert', name: 'Expired Signing Certificate', severity: 'high', description: 'Signing certificate has expired.', cwe: 'CWE-298', owasp: 'M3', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'weak_sig', name: 'Weak Signature Algorithm', severity: 'high', description: 'Weak signature algorithm used.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CODE-1', category: 'code_quality' },
    { id: 'world_readable', name: 'World-Readable Files', severity: 'high', description: 'World-readable files can be read by any installed app.', cwe: 'CWE-276', owasp: 'M2', masvs: 'MASVS-STORAGE-2', category: 'storage' },
    { id: 'world_writable', name: 'World-Writable Files', severity: 'high', description: 'World-writable files can be modified by any app.', cwe: 'CWE-276', owasp: 'M2', masvs: 'MASVS-STORAGE-2', category: 'storage' },
    { id: 'raw_query', name: 'Raw SQL Queries', severity: 'critical', description: 'Raw SQL queries vulnerable to injection.', cwe: 'CWE-89', owasp: 'M7', masvs: 'MASVS-PLATFORM-2', category: 'platform' },
    { id: 'cleartext_http', name: 'Cleartext HTTP Traffic', severity: 'high', description: 'Cleartext HTTP can be intercepted.', cwe: 'CWE-319', owasp: 'M3', masvs: 'MASVS-NETWORK-1', category: 'network' },
    { id: 'md5_used', name: 'MD5 Hash Used', severity: 'medium', description: 'MD5 is cryptographically broken.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-4', category: 'cryptography' },
    { id: 'sha1_used', name: 'SHA-1 Hash Used', severity: 'medium', description: 'SHA-1 is deprecated.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-4', category: 'cryptography' },
    { id: 'des_used', name: 'DES/3DES Cipher Used', severity: 'high', description: 'DES is obsolete. Use AES-256-GCM.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-3', category: 'cryptography' },
    { id: 'ecb_used', name: 'AES-ECB Mode Used', severity: 'high', description: 'ECB mode reveals patterns.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-3', category: 'cryptography' },
    { id: 'random_used', name: 'java.util.Random Used', severity: 'medium', description: 'Use SecureRandom for crypto.', cwe: 'CWE-330', owasp: 'M5', masvs: 'MASVS-CRYPTO-6', category: 'cryptography' },
    { id: 'null_cipher', name: 'NullCipher Usage', severity: 'critical', description: 'No actual encryption performed.', cwe: 'CWE-327', owasp: 'M5', masvs: 'MASVS-CRYPTO-3', category: 'cryptography' },
    { id: 'static_iv', name: 'Static IV Detected', severity: 'high', description: 'Static IV compromises ciphertext confidentiality.', cwe: 'CWE-329', owasp: 'M5', masvs: 'MASVS-CRYPTO-3', category: 'cryptography' },
    { id: 'hardcoded_key', name: 'Hardcoded Crypto Key', severity: 'critical', description: 'Hardcoded keys can be extracted.', cwe: 'CWE-321', owasp: 'M5', masvs: 'MASVS-CRYPTO-1', category: 'cryptography' }
  ];

  /**
   * Register a rule.
   */
  function registerRule(rule) {
    if (!rule) return;
    var id = rule.ruleId || rule.id || 'rule-' + rules.length;
    var exists = rules.some(function(r) { return (r.ruleId || r.id) === id; });
    if (exists) return;
    rules.push({
      id: id,
      name: rule.ruleName || rule.name || 'Unnamed Rule',
      severity: rule.severity || 'medium',
      description: rule.description || '',
      cwe: rule.cwe || '',
      owasp: rule.owasp || '',
      masvs: rule.masvs || '',
      category: rule.category || 'general',
      source: rule.source || 'built-in',
      enabled: enabledRules[id] !== false,
      builtIn: true
    });
  }

  /**
   * Register multiple rules at once.
   */
  function registerRules(arr) {
    if (!arr || !arr.length) return;
    for (var i = 0; i < arr.length; i++) {
      registerRule(arr[i]);
    }
  }

  /**
   * Discover rules from MSAS scanner modules.
   * Scans the MSAS namespace for modules that have a .rules array property.
   */
  function discoverRules() {
    var found = 0;
    for (var key in MSAS) {
      if (MSAS.hasOwnProperty(key) && MSAS[key] && Array.isArray(MSAS[key].rules)) {
        registerRules(MSAS[key].rules);
        found += MSAS[key].rules.length;
      }
    }
    // Also check the global engine rules if available
    if (typeof ANDROID_RULES !== 'undefined') registerRules(ANDROID_RULES);
    if (typeof IOS_RULES !== 'undefined') registerRules(IOS_RULES);
    return found;
  }

  /**
   * Initialize with built-in rules.
   */
  function initRules() {
    registerRules(knownRules);
  }

  /**
   * Get all registered rules.
   */
  function getRules() {
    return rules.slice();
  }

  /**
   * Get only enabled rules.
   */
  function getEnabledRules() {
    return rules.filter(function(r) { return r.enabled !== false; });
  }

  /**
   * Get only disabled rules.
   */
  function getDisabledRules() {
    return rules.filter(function(r) { return r.enabled === false; });
  }

  // ── Rule Toggling ──────────────────────────────────────────

  /**
   * Enable or disable a rule by ID.
   */
  function setRuleEnabled(ruleId, enabled) {
    var rule = rules.find(function(r) { return r.id === ruleId; });
    if (!rule) return false;
    rule.enabled = enabled;
    enabledRules[ruleId] = enabled;
    return true;
  }

  /**
   * Toggle a rule's enabled state.
   */
  function toggleRule(ruleId) {
    var rule = rules.find(function(r) { return r.id === ruleId; });
    if (!rule) return false;
    rule.enabled = !rule.enabled;
    enabledRules[ruleId] = rule.enabled;
    return rule.enabled;
  }

  /**
   * Enable/disable all rules.
   */
  function setAllRules(enabled) {
    for (var i = 0; i < rules.length; i++) {
      rules[i].enabled = enabled;
      enabledRules[rules[i].id] = enabled;
    }
  }

  // ── Custom Rules ───────────────────────────────────────────

  /**
   * Create a custom rule.
   * @param {Object} opts - { name, severity, description, pattern, category, cwe, owasp, masvs }
   * @returns {Object} The created rule
   */
  function createCustomRule(opts) {
    if (!opts || !opts.name || !opts.pattern) return null;

    var id = 'custom-' + Date.now() + '-' + Math.random().toString(36).substr(2, 4);
    var rule = {
      id: id,
      name: opts.name,
      severity: opts.severity || 'medium',
      description: opts.description || 'Custom security rule',
      pattern: opts.pattern,
      category: opts.category || 'custom',
      cwe: opts.cwe || '',
      owasp: opts.owasp || '',
      masvs: opts.masvs || '',
      source: 'custom',
      enabled: true,
      builtIn: false
    };

    customRules.push(rule);
    rules.push(rule);
    return rule;
  }

  /**
   * Delete a custom rule.
   */
  function deleteCustomRule(ruleId) {
    rules = rules.filter(function(r) { return r.id !== ruleId; });
    customRules = customRules.filter(function(r) { return r.id !== ruleId; });
    delete enabledRules[ruleId];
  }

  /**
   * Get all custom rules.
   */
  function getCustomRules() {
    return customRules.slice();
  }

  // ── Profiles ───────────────────────────────────────────────

  /**
   * Save current configuration as a named profile.
   */
  function saveProfile(name) {
    name = name || currentProfile;
    var profile = {
      name: name,
      timestamp: new Date().toISOString(),
      enabledRules: JSON.parse(JSON.stringify(enabledRules)),
      customRules: JSON.parse(JSON.stringify(customRules))
    };
    profiles[name] = profile;
    persistProfiles();
    currentProfile = name;
    return profile;
  }

  /**
   * Load a profile by name.
   */
  function loadProfile(name) {
    var profile = profiles[name];
    if (!profile) return false;

    // Apply enabled states
    for (var id in profile.enabledRules) {
      enabledRules[id] = profile.enabledRules[id];
    }
    for (var i = 0; i < rules.length; i++) {
      if (enabledRules[rules[i].id] !== undefined) {
        rules[i].enabled = enabledRules[rules[i].id];
      }
    }

    // Add custom rules from profile (if any that don't exist yet)
    var existingIds = {};
    for (var j = 0; j < customRules.length; j++) {
      existingIds[customRules[j].id] = true;
    }
    for (var k = 0; k < (profile.customRules || []).length; k++) {
      var cr = profile.customRules[k];
      if (!existingIds[cr.id]) {
        customRules.push(cr);
        rules.push(cr);
      }
    }

    currentProfile = name;
    return true;
  }

  /**
   * Delete a profile.
   */
  function deleteProfile(name) {
    delete profiles[name];
    persistProfiles();
  }

  /**
   * List all saved profiles.
   */
  function getProfiles() {
    var result = [];
    for (var name in profiles) {
      result.push({
        name: name,
        timestamp: profiles[name].timestamp,
        ruleCount: Object.keys(profiles[name].enabledRules || {}).length,
        customCount: (profiles[name].customRules || []).length
      });
    }
    return result;
  }

  /**
   * Get current profile name.
   */
  function getCurrentProfile() {
    return currentProfile;
  }

  function persistProfiles() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(profiles));
    } catch (e) {
      console.warn('[RuleEditor] Failed to persist profiles:', e.message);
    }
  }

  function loadProfiles() {
    try {
      var data = localStorage.getItem(STORAGE_KEY);
      if (data) {
        profiles = JSON.parse(data);
        // Load last used profile
        var lastProfile = Object.keys(profiles).pop();
        if (lastProfile) {
          loadProfile(lastProfile);
        }
      }
    } catch (e) {
      console.warn('[RuleEditor] Failed to load profiles:', e.message);
    }
  }

  // ── Initialization ─────────────────────────────────────────

  function init() {
    loadProfiles();
    initRules();
    return {
      totalRules: rules.length,
      enabledCount: getEnabledRules().length,
      disabledCount: getDisabledRules().length,
      customCount: customRules.length
    };
  }

  // ── UI Rendering ───────────────────────────────────────────

  /**
   * Render the full rule editor UI.
   */
  function renderHtml() {
    var enabled = getEnabledRules();
    var disabled = getDisabledRules();
    var custom = getCustomRules();
    var profileList = getProfiles();

    var html = '<div class="rule-editor">';

    // Toolbar
    html += '<div class="rule-editor-toolbar">';
    html += '  <button class="batch-btn primary" data-action="enable-all">Enable All</button>';
    html += '  <button class="batch-btn" data-action="disable-all">Disable All</button>';
    html += '  <button class="batch-btn" data-action="add-custom">+ Custom Rule</button>';
    html += '  <span class="rule-editor-stats">' + enabled.length + ' enabled · ' + disabled.length + ' disabled · ' + custom.length + ' custom</span>';
    html += '</div>';

    // Profile bar
    html += '<div class="rule-editor-profiles">';
    html += '  <label>Profile:</label>';
    html += '  <select id="ruleProfileSelect" class="rule-profile-select">';
    html += '    <option value="__default__">Default</option>';
    for (var p = 0; p < profileList.length; p++) {
      html += '    <option value="' + esc(profileList[p].name) + '"' + (currentProfile === profileList[p].name ? ' selected' : '') + '>' + esc(profileList[p].name) + '</option>';
    }
    html += '  </select>';
    html += '  <button class="batch-btn" data-action="save-profile">💾 Save</button>';
    html += '  <button class="batch-btn" data-action="delete-profile" id="deleteProfileBtn">🗑️ Delete</button>';
    html += '</div>';

    // Search/filter
    html += '<div class="rule-editor-search">';
    html += '  <input type="search" id="ruleSearchInput" placeholder="Search rules by name, ID, CWE, MASVS…" class="rule-search-input">';
    html += '  <select id="ruleFilterSelect" class="rule-filter-select">';
    html += '    <option value="all">All Rules</option>';
    html += '    <option value="enabled">Enabled</option>';
    html += '    <option value="disabled">Disabled</option>';
    html += '    <option value="custom">Custom</option>';
    html += '  </select>';
    html += '</div>';

    // Rules list
    html += '<div class="rule-editor-list" id="ruleEditorList">';
    html += renderRuleList();
    html += '</div>';

    // Custom rule form (hidden by default)
    html += '<div class="rule-custom-form" id="ruleCustomForm" style="display:none">';
    html += '  <h4>Create Custom Rule</h4>';
    html += '  <div class="rule-custom-grid">';
    html += '    <label>Rule Name <input type="text" id="customRuleName" placeholder="e.g., Detect Stripe Key" class="rule-input"></label>';
    html += '    <label>Severity <select id="customRuleSeverity" class="rule-input"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></label>';
    html += '    <label>Search Pattern <input type="text" id="customRulePattern" placeholder="e.g., sk_live_ or regex pattern" class="rule-input"></label>';
    html += '    <label>Description <input type="text" id="customRuleDesc" placeholder="What this rule detects" class="rule-input"></label>';
    html += '    <label>Category <input type="text" id="customRuleCategory" placeholder="e.g., secrets, crypto" class="rule-input"></label>';
    html += '    <label>CWE <input type="text" id="customRuleCwe" placeholder="e.g., CWE-798" class="rule-input"></label>';
    html += '    <label>MASVS <input type="text" id="customRuleMasvs" placeholder="e.g., MASVS-STORAGE-14" class="rule-input"></label>';
    html += '  </div>';
    html += '  <div class="rule-custom-actions">';
    html += '    <button class="batch-btn primary" data-action="save-custom">Save Rule</button>';
    html += '    <button class="batch-btn" data-action="cancel-custom">Cancel</button>';
    html += '  </div>';
    html += '</div>';

    html += '</div>';
    return html;
  }

  /**
   * Render the rule list (rows of rules).
   * @param {Array} filteredRules - Optional pre-filtered rule array. If omitted, renders all rules.
   */
  function renderRuleList(filteredRules) {
    var list = filteredRules || rules.slice();

    if (list.length === 0) {
      if (rules.length === 0) {
        return '<div class="no-data">No rules loaded. Run an analysis first to populate the rule list.</div>';
      }
      return '<div class="no-data">No rules match the current filter or search.</div>';
    }

    // Sort: enabled first, then by category, then by name
    list.sort(function(a, b) {
      if (a.enabled !== b.enabled) return a.enabled ? -1 : 1;
      if (a.category !== b.category) return (a.category || '').localeCompare(b.category || '');
      return (a.name || '').localeCompare(b.name || '');
    });

    var html = '';
    var currentCat = '';

    for (var i = 0; i < list.length; i++) {
      var rule = list[i];

      // Category header
      var cat = rule.category || 'general';
      if (cat !== currentCat) {
        if (currentCat !== '') html += '</div>';
        currentCat = cat;
        var catCount = list.filter(function(r) { return (r.category || 'general') === cat; }).length;
        html += '<div class="rule-category-header">' + esc(cat.toUpperCase()) + ' (' + catCount + ')</div>';
        html += '<div class="rule-category-group">';
      }

      html += '<div class="rule-row ' + (rule.enabled ? 'enabled' : 'disabled') + '" data-rule-id="' + esc(rule.id) + '">';
      html += '  <label class="rule-toggle">';
      html += '    <input type="checkbox" ' + (rule.enabled ? 'checked' : '') + ' data-rule-id="' + esc(rule.id) + '" aria-label="Toggle ' + esc(rule.name) + '">';
      html += '    <span class="rule-toggle-slider"></span>';
      html += '  </label>';
      html += '  <div class="rule-info">';
      html += '    <span class="rule-name">' + esc(rule.name) + '</span>';
      html += '    <span class="rule-meta">';
      if (rule.severity) html += '<span class="rule-severity ' + rule.severity + '">' + rule.severity + '</span>';
      if (rule.cwe) html += '<span class="rule-tag">' + esc(rule.cwe) + '</span>';
      if (rule.masvs) html += '<span class="rule-tag">' + esc(rule.masvs) + '</span>';
      if (rule.source === 'custom') html += '<span class="rule-tag custom">custom</span>';
      html += '    </span>';
      html += '    <span class="rule-desc">' + esc(rule.description || '').substring(0, 120) + '</span>';
      html += '  </div>';
      if (!rule.builtIn) {
        html += '  <button class="rule-delete-btn" data-rule-id="' + esc(rule.id) + '" title="Delete custom rule">✕</button>';
      }
      html += '</div>';
    }

    if (currentCat !== '') html += '</div>';
    return html;
  }

  // ── Event Binding ──────────────────────────────────────────

  /**
   * Wire up rule editor UI events.
   */
  function bindEvents(container) {
    if (!container) return;

    // Enable all
    container.querySelector('[data-action="enable-all"]').addEventListener('click', function() {
      setAllRules(true);
      refreshList(container);
    });

    // Disable all
    container.querySelector('[data-action="disable-all"]').addEventListener('click', function() {
      setAllRules(false);
      refreshList(container);
    });

    // Show custom form
    container.querySelector('[data-action="add-custom"]').addEventListener('click', function() {
      var form = document.getElementById('ruleCustomForm');
      if (form) form.style.display = 'block';
    });

    // Save custom
    container.querySelector('[data-action="save-custom"]').addEventListener('click', function() {
      var name = document.getElementById('customRuleName');
      var sev = document.getElementById('customRuleSeverity');
      var pattern = document.getElementById('customRulePattern');
      var desc = document.getElementById('customRuleDesc');
      var cat = document.getElementById('customRuleCategory');
      var cwe = document.getElementById('customRuleCwe');
      var masvs = document.getElementById('customRuleMasvs');

      if (!name || !name.value.trim()) { toast('Rule name is required', 'error'); return; }
      if (!pattern || !pattern.value.trim()) { toast('Search pattern is required', 'error'); return; }

      createCustomRule({
        name: name.value.trim(),
        severity: sev ? sev.value : 'high',
        pattern: pattern.value.trim(),
        description: desc ? desc.value.trim() : 'Custom rule: ' + name.value.trim(),
        category: cat ? cat.value.trim() : 'custom',
        cwe: cwe ? cwe.value.trim() : '',
        masvs: masvs ? masvs.value.trim() : ''
      });

      // Clear form
      if (name) name.value = '';
      if (pattern) pattern.value = '';
      if (desc) desc.value = '';
      if (cat) cat.value = '';
      if (cwe) cwe.value = '';
      if (masvs) masvs.value = '';
      if (document.getElementById('ruleCustomForm')) {
        document.getElementById('ruleCustomForm').style.display = 'none';
      }

      toast('Custom rule created', 'success');
      refreshList(container);
    });

    // Cancel custom
    container.querySelector('[data-action="cancel-custom"]').addEventListener('click', function() {
      var form = document.getElementById('ruleCustomForm');
      if (form) form.style.display = 'none';
    });

    // Toggle individual rules (delegates to reusable helper for re-bind after re-render)
    bindToggleEvents(container);

    // Delete custom rules (delegates to reusable helper)
    bindDeleteEvents(container);

    // Profile save
    container.querySelector('[data-action="save-profile"]').addEventListener('click', function() {
      var name = prompt('Profile name:', currentProfile);
      if (name && name.trim()) {
        saveProfile(name.trim());
        toast('Profile "' + name.trim() + '" saved', 'success');
        // Refresh profile dropdown
        var select = document.getElementById('ruleProfileSelect');
        if (select) {
          var options = select.querySelectorAll('option');
          var exists = Array.from(options).some(function(o) { return o.value === name.trim(); });
          if (!exists) {
            var opt = document.createElement('option');
            opt.value = name.trim();
            opt.textContent = name.trim();
            opt.selected = true;
            select.appendChild(opt);
          }
        }
      }
    });

    // Profile select change
    container.querySelector('#ruleProfileSelect').addEventListener('change', function() {
      var name = this.value;
      if (name === '__default__') {
        // Reset to defaults
        for (var i = 0; i < rules.length; i++) {
          if (rules[i].builtIn) rules[i].enabled = true;
        }
        currentProfile = 'default';
      } else if (name) {
        loadProfile(name);
      }
      refreshList(container);
    });

    // Search input
    container.querySelector('#ruleSearchInput').addEventListener('input', function() {
      filterAndRender(container);
    });

    // Filter select
    container.querySelector('#ruleFilterSelect').addEventListener('change', function() {
      filterAndRender(container);
    });
  }

  function bindToggleEvents(container) {
    if (!container) return;
    container.querySelectorAll('[data-rule-id] input[type="checkbox"]').forEach(function(cb) {
      cb.addEventListener('change', function() {
        var id = this.getAttribute('data-rule-id');
        setRuleEnabled(id, this.checked);
        var row = this.closest('.rule-row');
        if (row) {
          row.className = 'rule-row ' + (this.checked ? 'enabled' : 'disabled');
        }
      });
    });
  }

  function bindDeleteEvents(container) {
    if (!container) return;
    container.querySelectorAll('.rule-delete-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        var id = this.getAttribute('data-rule-id');
        if (id && confirm('Delete this custom rule?')) {
          deleteCustomRule(id);
          toast('Custom rule deleted', 'success');
          refreshList(container);
        }
      });
    });
  }

  function filterAndRender(container) {
    if (!container) container = document.querySelector('.rule-editor');
    if (!container) return;
    
    var searchInput = container.querySelector('#ruleSearchInput');
    var filterSelect = container.querySelector('#ruleFilterSelect');
    var q = searchInput ? searchInput.value.trim().toLowerCase() : '';
    var filter = filterSelect ? filterSelect.value : 'all';

    var filtered = rules.filter(function(r) {
      if (filter === 'enabled' && !r.enabled) return false;
      if (filter === 'disabled' && r.enabled) return false;
      if (filter === 'custom' && r.builtIn) return false;
      if (q) {
        var inName = (r.name || '').toLowerCase().indexOf(q) >= 0;
        var inId = (r.id || '').toLowerCase().indexOf(q) >= 0;
        var inCwe = (r.cwe || '').toLowerCase().indexOf(q) >= 0;
        var inMasvs = (r.masvs || '').toLowerCase().indexOf(q) >= 0;
        var inDesc = (r.description || '').toLowerCase().indexOf(q) >= 0;
        if (!inName && !inId && !inCwe && !inMasvs && !inDesc) return false;
      }
      return true;
    });

    var list = container.querySelector('#ruleEditorList');
    if (list) {
      list.innerHTML = renderRuleList(filtered);
    }
    // Re-bind events for the new DOM elements (lost after innerHTML replacement)
    bindToggleEvents(container);
    bindDeleteEvents(container);
  }

  function refreshList(container) {
    filterAndRender(container);
  }

  function esc(str) {
    if (str == null) return '';
    var d = document.createElement('div');
    d.textContent = String(str);
    return d.innerHTML;
  }

  function toast(msg, type) {
    var c = document.getElementById('toastContainer');
    if (!c) return;
    var t = document.createElement('div');
    t.className = 'toast ' + (type || 'info');
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(function() { t.remove(); }, 3000);
  }

  return {
    init: init,
    registerRule: registerRule,
    registerRules: registerRules,
    discoverRules: discoverRules,
    getRules: getRules,
    getEnabledRules: getEnabledRules,
    getDisabledRules: getDisabledRules,
    setRuleEnabled: setRuleEnabled,
    toggleRule: toggleRule,
    setAllRules: setAllRules,
    createCustomRule: createCustomRule,
    deleteCustomRule: deleteCustomRule,
    getCustomRules: getCustomRules,
    saveProfile: saveProfile,
    loadProfile: loadProfile,
    deleteProfile: deleteProfile,
    getProfiles: getProfiles,
    getCurrentProfile: getCurrentProfile,
    renderHtml: renderHtml,
    renderRuleList: renderRuleList,
    bindEvents: bindEvents
  };
})();
