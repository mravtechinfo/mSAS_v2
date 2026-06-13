/**
 * mSAS v2 — Unit Tests: AI/ML & ADB Scanners (Phases 5-6)
 * 
 * Tests for AI-1 through AI-10 and ADB-1 through ADB-7 scanners.
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.AIMLScanner (Phase 5)', () => {
  it('should detect on-device ML models', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['.tflite', 'TFLite', 'Interpreter'],
    });
    const modelFindings = findings.filter(f => f.ruleId === 'mastg-ai-1-on-device-models');
    expect(modelFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect AI API key patterns', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['sk-proj-abc123', 'openai', 'api.openai.com'],
    });
    const keyFindings = findings.filter(f => f.ruleId === 'mastg-ai-2-api-keys');
    expect(keyFindings.length).toBeGreaterThanOrEqual(1);
    expect(keyFindings[0].severity).toBe('issue');
  });

  it('should detect AI SDK usage', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['Lcom/openai/client', 'Lcom/anthropic'],
    });
    const sdkFindings = findings.filter(f => f.ruleId === 'mastg-ai-5-sdk-detected');
    expect(sdkFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect prompt patterns', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['systemPrompt', 'chatCompletion', 'Lcom/openai/client/chat'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect RAG and vector DB usage', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['chroma', 'pinecone', 'faiss', 'embedding'],
    });
    const ragFindings = findings.filter(f => f.ruleId === 'mastg-ai-10-rag-vector-db');
    expect(ragFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should return informational finding when no AI/ML detected', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['hello', 'world'],
    });
    const noAI = findings.find(f => f.ruleId === 'mastg-ai-no-ai-detected');
    expect(noAI).toBeTruthy();
  });

  it('should produce findings in v1 format', () => {
    const findings = MSAS.AIMLScanner.scan({
      strings: ['openai', 'sk-'],
    });
    if (findings.length > 0) {
      expect(findings[0]).toHaveProperty('ruleId');
      expect(findings[0]).toHaveProperty('severity');
      expect(findings[0]).toHaveProperty('cwe');
      expect(findings[0]).toHaveProperty('owasp');
      expect(findings[0]).toHaveProperty('masvs');
    }
  });
});

describe('MSAS.ADBScanner (Phase 6)', () => {
  it('should detect Android intent patterns for ADB fuzzing', () => {
    const findings = MSAS.ADBScanner.scan({
      strings: ['Landroid/content/Intent', 'Landroid/content/IntentFilter', 'startActivity'],
    });
    const intentFindings = findings.filter(f => f.ruleId === 'mastg-adb-1-intent-fuzzing');
    expect(intentFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect WebView debugging patterns', () => {
    const findings = MSAS.ADBScanner.scan({
      strings: ['setWebContentsDebuggingEnabled', 'Landroid/webkit/WebView'],
    });
    const debugFindings = findings.filter(f => f.ruleId === 'mastg-adb-4-webview-debug');
    expect(debugFindings.length).toBeGreaterThanOrEqual(1);
    expect(debugFindings[0].severity).toBe('issue');
  });

  it('should detect logcat leakage patterns', () => {
    const findings = MSAS.ADBScanner.scan({
      strings: ['Landroid/util/Log', 'Log.d', 'adb logcat'],
    });
    const logFindings = findings.filter(f => f.ruleId === 'mastg-adb-7-logcat');
    expect(logFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should produce findings in v1 format', () => {
    const findings = MSAS.ADBScanner.scan({
      strings: ['Landroid/content/Intent', 'Landroid/webkit/WebView'],
    });
    if (findings.length > 0) {
      expect(findings[0]).toHaveProperty('ruleId');
      expect(findings[0]).toHaveProperty('severity');
      expect(findings[0]).toHaveProperty('description');
    }
  });
});
