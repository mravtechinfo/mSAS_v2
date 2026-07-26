/**
 * mSAS v2 — Shared Entropy Module (BASE-1)
 *
 * Consolidated Shannon entropy calculation, secret detection, and confidence
 * scoring. Previously duplicated across apk-auditor/src/core/entropy.js and
 * ipa-auditor/src/core/entropy.js. This shared version is the canonical source
 * for all new entropy-related code, with the full set of SECRET_DETECTORS.
 *
 * The existing APK/IPA specific versions remain for backward compatibility.
 *
 * Usage:
 *   var h = MSAS.SharedEntropy.shannonEntropy("abc123"); // 2.58
 *   var secrets = MSAS.SharedEntropy.detectSecrets(dexStringContent);
 *   var conf = MSAS.SharedEntropy.computeConfidence(finding);
 */

var MSAS = MSAS || {};
MSAS.SharedEntropy = (function() {
  'use strict';

  // ── Shannon Entropy ────────────────────────────────────────

  /**
   * Compute Shannon entropy of a string.
   * H = -Σ(p(i) * log2(p(i))) where p(i) = freq(i) / len
   * @param {string} str - Input string
   * @returns {number} Entropy value between 0 and ~8 (for ASCII)
   */
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    var freq = {};
    for (var i = 0; i < str.length; i++) {
      var c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    var h = 0;
    var len = str.length;
    for (var ch in freq) {
      if (freq.hasOwnProperty(ch)) {
        var p = freq[ch] / len;
        h -= p * Math.log2(p);
      }
    }
    return h;
  }

  // ── Placeholder Detection ──────────────────────────────────

  var COMMON_WORDS = [
    'placeholder', 'example', 'lorem', 'ipsum', 'test', 'testing',
    'demo', 'sample', 'password', 'passw0rd', 'changeme', 'default',
    'admin', 'username', 'guest', 'unknown', 'null', 'undefined',
    'foobar', 'foo', 'bar', 'true', 'false', 'yes', 'no',
    'enabled', 'disabled', 'required', 'optional', 'localhost',
    'apikey', 'token', 'secret', 'key', 'auth', 'authorization',
    'bearer', 'username', 'email', 'phone', 'name', 'value',
    'data', 'string'
  ];

  var COMMON_WORDS_SET = {};
  for (var wi = 0; wi < COMMON_WORDS.length; wi++) {
    COMMON_WORDS_SET[COMMON_WORDS[wi]] = true;
  }

  /**
   * Check if a string looks like a placeholder/template value.
   * @param {string} str
   * @returns {boolean}
   */
  function looksLikePlaceholder(str) {
    if (!str) return true;
    var s = String(str).toLowerCase();
    if (s.length < 4) return true;
    if (/^x+$/.test(s) || /^[*]+$/.test(s) || /^[.]+$/.test(s)) return true;
    if (/^(test|demo|example|sample|placeholder|todo)[_-]?/.test(s)) return true;
    if (/your[_-]?(api|secret|token|key|password)/.test(s)) return true;
    if (/<[a-z]+>/.test(s)) return true;
    if (/\$\{[a-z]+\}/i.test(s)) return true;
    if (COMMON_WORDS_SET[s]) return true;
    return false;
  }

  // ── High Entropy Secret Detection ──────────────────────────

  /**
   * Determine if a string is a high-entropy secret (candidate API key, token, etc.)
   * @param {string} value - The string to check
   * @param {Object} [opts]
   * @param {number} [opts.minEntropy=4.0] - Minimum entropy for generic strings
   * @param {number} [opts.minBase64Entropy=4.5] - Minimum entropy for base64 strings
   * @param {number} [opts.minHexEntropy=3.0] - Minimum entropy for hex strings
   * @param {number} [opts.minLength=16] - Minimum length to consider
   * @returns {{match: boolean, entropy?: number, threshold?: number, kind?: string, reason?: string}}
   */
  function isHighEntropySecret(value, opts) {
    var o = opts || {};
    var minEntropy = o.minEntropy != null ? o.minEntropy : 4.0;
    var minBase64Entropy = o.minBase64Entropy != null ? o.minBase64Entropy : 4.5;
    var minHexEntropy = o.minHexEntropy != null ? o.minHexEntropy : 3.0;
    var minLength = o.minLength != null ? o.minLength : 16;

    if (!value || value.length < minLength) return { match: false, reason: 'too-short' };
    if (looksLikePlaceholder(value)) return { match: false, reason: 'placeholder' };

    var repeated = /^(.)\1+$/.test(value);
    if (repeated) return { match: false, reason: 'repeated-char' };

    var entropy = shannonEntropy(value);
    var isHex = /^[0-9a-fA-F]+$/.test(value);
    var isBase64 = /^[A-Za-z0-9+/=_-]+$/.test(value);
    var kind = 'generic';
    var threshold = minEntropy;
    if (isHex) { kind = 'hex'; threshold = minHexEntropy; }
    else if (isBase64) { kind = 'base64'; threshold = minBase64Entropy; }

    return {
      match: entropy >= threshold,
      entropy: +entropy.toFixed(2),
      threshold: threshold,
      kind: kind
    };
  }

  // ── Secret Detectors (full set, matching APK/IPA entropy) ───

  var SECRET_DETECTORS = [
    {
      id: 'aws_access_key_id',
      name: 'AWS Access Key ID',
      pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b/g,
      severity: 'high', confidence: 95,
      cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
      description: 'AWS access key ID found. Rotate immediately and remove from binary.',
    },
    {
      id: 'aws_secret_access_key',
      name: 'AWS Secret Access Key',
      pattern: /\b((?:[A-Za-z0-9+/]{40}))\b/g,
      check: function(m) {
        return /aws[_-]?secret|secret[_-]?access[_-]?key/i.test(m.context || '') &&
               shannonEntropy(m.value) >= 4.5;
      },
      severity: 'high', confidence: 80,
      cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
      description: 'AWS secret access key candidate (40-char base64 near AWS context).',
    },
    {
      id: 'google_api_key',
      name: 'Google API Key',
      pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
      description: 'Google API key in code. Restrict by referrer/bundle and rotate.',
    },
    {
      id: 'google_oauth_token',
      name: 'Google OAuth Access Token',
      pattern: /\bya29\.[0-9A-Za-z\-_]+\b/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'Google OAuth access token detected.',
    },
    {
      id: 'firebase_url',
      name: 'Firebase Database URL',
      pattern: /\bhttps?:\/\/[a-zA-Z0-9-]+\.(?:firebaseio\.com|firebasedatabase\.app)[^\s"'<>]*/gi,
      severity: 'warning', confidence: 85,
      cwe: 'CWE-200', owasp: 'M1', masvs: 'STORAGE-12',
      description: 'Firebase database URL found. Verify security rules.',
    },
    {
      id: 'github_token',
      name: 'GitHub Personal Access Token',
      pattern: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
      severity: 'high', confidence: 95,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'GitHub PAT found. Revoke and rotate.',
    },
    {
      id: 'slack_token',
      name: 'Slack Token',
      pattern: /\b(xox[abprs]-[A-Za-z0-9-]{10,})\b/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'Slack token found.',
    },
    {
      id: 'slack_webhook',
      name: 'Slack Webhook URL',
      pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+\b/g,
      severity: 'high', confidence: 95,
      cwe: 'CWE-200', owasp: 'M1',
      description: 'Slack webhook URL embedded.',
    },
    {
      id: 'stripe_secret',
      name: 'Stripe Secret Key',
      pattern: /\b(sk_(?:test|live)_[0-9A-Za-z]{16,99})\b/g,
      severity: 'high', confidence: 95,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'Stripe secret/restricted key. Never ship secret keys to clients.',
    },
    {
      id: 'stripe_publishable',
      name: 'Stripe Publishable Key',
      pattern: /\b(pk_(?:test|live)_[0-9A-Za-z]{16,99})\b/g,
      severity: 'info', confidence: 95,
      cwe: '', owasp: '',
      description: 'Stripe publishable key (safe to expose, but tag for tracking).',
    },
    {
      id: 'twilio_sid',
      name: 'Twilio Account SID',
      pattern: /\b(AC[a-f0-9]{32})\b/g,
      severity: 'warning', confidence: 80,
      cwe: 'CWE-200', owasp: 'M9',
      description: 'Twilio account SID (low risk alone but tag for rotation review).',
    },
    {
      id: 'twilio_auth_token',
      name: 'Twilio Auth Token',
      pattern: /\b([a-f0-9]{32})\b/g,
      check: function(m) { return /twilio.{0,20}(auth|token)/i.test(m.context || ''); },
      severity: 'high', confidence: 70,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'Twilio auth token candidate.',
    },
    {
      id: 'sendgrid_api',
      name: 'SendGrid API Key',
      pattern: /\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b/g,
      severity: 'high', confidence: 95,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'SendGrid API key.',
    },
    {
      id: 'mailgun_api',
      name: 'Mailgun API Key',
      pattern: /\b(key-[a-f0-9]{32})\b/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-798', owasp: 'M9',
      description: 'Mailgun API key.',
    },
    {
      id: 'square_token',
      name: 'Square Access Token',
      pattern: /\b(sq0(?:atp|csp)-[A-Za-z0-9_-]{22,43})\b/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-798',
      description: 'Square access token.',
    },
    {
      id: 'paypal_token',
      name: 'PayPal/Braintree Token',
      pattern: /\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b/gi,
      severity: 'high', confidence: 95,
      cwe: 'CWE-798',
      description: 'PayPal/Braintree access token.',
    },
    {
      id: 'private_key_pem',
      name: 'Private Key (PEM)',
      pattern: /-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED|ANY)?\s*PRIVATE KEY-----/g,
      severity: 'high', confidence: 99,
      cwe: 'CWE-321', owasp: 'M9',
      description: 'PEM-encoded private key embedded in the bundle.',
    },
    {
      id: 'pkcs12_marker',
      name: 'PKCS12 / .p12 / .pfx Reference',
      pattern: /\b(?:\.p12|\.pfx|PKCS12)\b/g,
      severity: 'warning', confidence: 60,
      cwe: 'CWE-321',
      description: 'PKCS#12 reference (may indicate embedded cert+key). Verify the .p12 is protected.',
    },
    {
      id: 'jwt_token',
      name: 'JWT Token',
      pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      severity: 'warning', confidence: 80,
      cwe: 'CWE-798',
      description: 'JWT token detected in code or strings. Verify it is not a long-lived secret.',
    },
    {
      id: 'generic_bearer',
      name: 'Bearer Token Header',
      pattern: /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._\-]{20,})/g,
      severity: 'high', confidence: 75,
      cwe: 'CWE-798',
      description: 'Hardcoded Bearer authorization header.',
    },
    {
      id: 'basic_auth_url',
      name: 'Basic Auth in URL',
      pattern: /\b(?:https?|ftp):\/\/[^\s:@\/]+:[^\s@\/]+@[^\s'"]+/g,
      severity: 'high', confidence: 90,
      cwe: 'CWE-522',
      description: 'URL contains embedded credentials (user:pass@host).',
    },
    {
      id: 'high_entropy_assigned_secret',
      name: 'High-Entropy Hardcoded Secret',
      pattern: /(?:secret|api[_-]?key|api[_-]?secret|access[_-]?token|client[_-]?secret|auth[_-]?token|private[_-]?key|encryption[_-]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-.]{16,})["']/gi,
      check: function(m) {
        var r = isHighEntropySecret(m.value, { minEntropy: 4.0, minBase64Entropy: 4.3 });
        return r.match;
      },
      severity: 'high', confidence: 70,
      cwe: 'CWE-798', owasp: 'M9', masvs: 'STORAGE-14',
      description: 'A high-entropy string is assigned to a "secret"-like key.',
    }
  ];

  // ── Secret Detection ───────────────────────────────────────

  /**
   * Scan text for secrets from the SECRET_DETECTORS data-driven rules.
   * @param {string} text - The text to scan (e.g., DEX strings content)
   * @param {Object} [opts] - Optional options
   * @returns {Array} Array of finding objects
   */
  function detectSecrets(text, opts) {
    if (!text) return [];
    var findings = [];
    for (var di = 0; di < SECRET_DETECTORS.length; di++) {
      var det = SECRET_DETECTORS[di];
      det.pattern.lastIndex = 0;
      var m;
      while ((m = det.pattern.exec(text)) !== null) {
        var value = m[1] || m[0];
        var matchStr = m[0];
        var ctxStart = Math.max(0, m.index - 64);
        var ctxEnd = Math.min(text.length, m.index + matchStr.length + 64);
        var context = text.slice(ctxStart, ctxEnd);
        if (det.check && !det.check({ value: value, context: context, match: matchStr })) {
          if (m.index === det.pattern.lastIndex) det.pattern.lastIndex++;
          continue;
        }
        var entropy = shannonEntropy(value);
        findings.push({
          ruleId: det.id,
          ruleName: det.name,
          severity: det.severity,
          confidence: det.confidence,
          description: det.description,
          cwe: det.cwe || '',
          owasp: det.owasp || '',
          masvs: det.masvs || '',
          match: matchStr,
          value: value,
          entropy: +entropy.toFixed(2),
          index: m.index
        });
        if (m.index === det.pattern.lastIndex) det.pattern.lastIndex++;
      }
    }
    return findings;
  }

  // ── Deduplication ──────────────────────────────────────────

  /**
   * Deduplicate findings by ruleId + file + line + match.
   * @param {Array} findings
   * @returns {Array} Deduplicated findings with occurrence counts
   */
  function dedupeFindings(findings) {
    if (!findings || !findings.length) return [];
    var seen = {};
    var out = [];
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      var key = [f.ruleId, f.file || '', f.line ?? '', (f.match || '').slice(0, 200), f.binaryOffset || ''].join('||');
      if (seen[key]) {
        seen[key].occurrences = (seen[key].occurrences || 1) + 1;
        continue;
      }
      var entry = shallowClone(f);
      entry.occurrences = 1;
      seen[key] = entry;
      out.push(entry);
    }
    return out;
  }

  // ── Confidence Scoring ─────────────────────────────────────

  /**
   * Compute a confidence score (0-100) for a finding.
   * Boosts confidence for high-entropy findings, reduces for test files/placeholders.
   * @param {Object} finding - Finding object with entropy, file, match fields
   * @returns {number} Confidence score 0-100
   */
  function computeConfidence(finding) {
    if (!finding) return 0;
    if (typeof finding.confidence === 'number') return finding.confidence;
    var conf = 50;
    if (finding.entropy != null) {
      if (finding.entropy >= 5.0) conf += 30;
      else if (finding.entropy >= 4.5) conf += 20;
      else if (finding.entropy >= 4.0) conf += 10;
      else if (finding.entropy < 3.0) conf -= 20;
    }
    if (finding.file && /test|fixture|mock|example|sample/i.test(finding.file)) conf -= 25;
    if (finding.match && looksLikePlaceholder(finding.match)) conf = Math.min(conf, 15);
    return Math.max(0, Math.min(100, conf));
  }

  /**
   * Map a confidence score to a label.
   * @param {number} c - Confidence score 0-100
   * @returns {string} 'high' | 'medium' | 'low' | 'noise'
   */
  function confidenceLabel(c) {
    if (c >= 85) return 'high';
    if (c >= 60) return 'medium';
    if (c >= 30) return 'low';
    return 'noise';
  }

  // ── Helpers ────────────────────────────────────────────────

  function shallowClone(obj) {
    if (obj == null || typeof obj !== 'object') return obj;
    if (Array.isArray(obj)) return obj.slice();
    var clone = {};
    for (var key in obj) {
      if (obj.hasOwnProperty(key)) {
        clone[key] = obj[key];
      }
    }
    return clone;
  }

  // ── Public API ─────────────────────────────────────────────

  return {
    shannonEntropy:      shannonEntropy,
    looksLikePlaceholder: looksLikePlaceholder,
    isHighEntropySecret:  isHighEntropySecret,
    detectSecrets:        detectSecrets,
    dedupeFindings:       dedupeFindings,
    computeConfidence:    computeConfidence,
    confidenceLabel:      confidenceLabel,
    SECRET_DETECTORS:     SECRET_DETECTORS
  };
})();
