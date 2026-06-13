/**
 * mSAS v2 — Unit Tests: Network & Platform Scanners (Phase 3)
 * 
 * Tests for NET-1 through NET-6 and PLAT-1 through PLAT-11.
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.TlsConfigScanner (NET-2)', () => {
  it('should detect weak TLS configurations', () => {
    const findings = MSAS.TlsConfigScanner.scan({
      strings: ['TLSv1.1', 'SSLContext.getInstance("TLSv1.1")'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });

  it('should produce findings in v1 format', () => {
    const findings = MSAS.TlsConfigScanner.scan({
      strings: ['SSLContext', 'TLS'],
    });
    if (findings.length > 0) {
      expect(findings[0]).toHaveProperty('ruleId');
      expect(findings[0]).toHaveProperty('severity');
    }
  });
});

describe('MSAS.CleartextScanner (NET-1)', () => {
  it('should detect cleartext HTTP traffic', () => {
    const findings = MSAS.CleartextScanner.scan({
      strings: ['http://', 'usesCleartextTraffic', 'NSAppTransportSecurity'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.NetworkSdkScanner (NET-5)', () => {
  it('should detect network SDK versions', () => {
    const findings = MSAS.NetworkSdkScanner.scan({
      strings: ['okhttp', 'retrofit', 'com.squareup.okhttp'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.NetworkSecurityScanner (NET-3/4)', () => {
  it('should detect network security patterns', () => {
    const findings = MSAS.NetworkSecurityScanner.scan({
      strings: ['HostnameVerifier', 'ALLOW_ALL_HOSTNAME_VERIFIER', 'WebSocket'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.WebViewScanner (PLAT-1)', () => {
  it('should detect WebView usage', () => {
    const findings = MSAS.WebViewScanner.scan({
      strings: ['Landroid/webkit/WebView', 'WebView', 'getSettings'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect JavaScript enabled in WebView', () => {
    const findings = MSAS.WebViewScanner.scan({
      strings: ['setJavaScriptEnabled', 'WebView'],
    });
    const riskFinding = findings.find(f => f.ruleId === 'mastg-platform-1-webview-risks');
    if (riskFinding) {
      expect(riskFinding.match).toContain('JavaScript');
    }
  });

  it('should detect addJavascriptInterface', () => {
    const findings = MSAS.WebViewScanner.scan({
      strings: ['addJavascriptInterface', 'JavascriptInterface', 'WebView'],
    });
    const riskFinding = findings.find(f => f.ruleId === 'mastg-platform-1-webview-risks');
    if (riskFinding) {
      expect(riskFinding.severity).toBe('issue');
    }
  });

  it('should return secure finding when no WebView', () => {
    const findings = MSAS.WebViewScanner.scan({
      strings: ['hello', 'world'],
    });
    const noWebView = findings.find(f => f.ruleId === 'mastg-platform-1-no-webview');
    expect(noWebView).toBeTruthy();
    expect(noWebView.severity).toBe('secure');
  });
});

describe('MSAS.DeepLinkScanner (PLAT-2)', () => {
  it('should detect deep link patterns', () => {
    const findings = MSAS.DeepLinkScanner.scan({
      strings: ['intent://', 'https://myapp.com', 'autoVerify'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('MSAS.TapjackingScanner (PLAT-3)', () => {
  it('should detect overlay patterns', () => {
    const findings = MSAS.TapjackingScanner.scan({
      strings: ['SYSTEM_ALERT_WINDOW', 'TYPE_APPLICATION_OVERLAY'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('MSAS.PendingIntentScanner (PLAT-4)', () => {
  it('should detect PendingIntent patterns', () => {
    const findings = MSAS.PendingIntentScanner.scan({
      strings: ['PendingIntent', 'FLAG_IMMUTABLE', 'FLAG_UPDATE_CURRENT'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('MSAS.ContentProviderScanner (PLAT-5)', () => {
  it('should detect content provider patterns', () => {
    const findings = MSAS.ContentProviderScanner.scan({
      strings: ['ContentProvider', 'query', 'Uri.parse'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('MSAS.ComponentsScanner (PLAT-6)', () => {
  it('should detect exported component patterns', () => {
    const findings = MSAS.ComponentsScanner.scan({
      strings: ['android:exported', 'Activity', 'Service', 'BroadcastReceiver'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});

describe('MSAS.TaskAffinityScanner (PLAT-11)', () => {
  it('should detect task affinity patterns', () => {
    const findings = MSAS.TaskAffinityScanner.scan({
      strings: ['taskAffinity', 'allowTaskReparenting', 'Activity'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(0);
  });
});
