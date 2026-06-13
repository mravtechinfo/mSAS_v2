/**
 * mSAS v2 — Unit Tests: CVSS 3.1 Calculator
 * 
 * Tests for MSAS.CVSS — vector parsing, base/temporal/environmental scoring.
 * CVSS 3.1 reference: https://www.first.org/cvss/v3-1/
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.CVSS', () => {
  describe('parseVector', () => {
    it('should parse a complete CVSS 3.1 vector', () => {
      const m = MSAS.CVSS.parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(m).toBeTruthy();
      expect(m.AV).toBe('N');
      expect(m.AC).toBe('L');
      expect(m.PR).toBe('N');
      expect(m.UI).toBe('N');
      expect(m.S).toBe('U');
      expect(m.C).toBe('H');
      expect(m.I).toBe('H');
      expect(m.A).toBe('H');
    });

    it('should parse vector with temporal metrics', () => {
      const m = MSAS.CVSS.parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H/RL:W/RC:C');
      expect(m).toBeTruthy();
      expect(m.E).toBe('H');
      expect(m.RL).toBe('W');
      expect(m.RC).toBe('C');
    });

    it('should parse vector with environmental metrics', () => {
      const m = MSAS.CVSS.parseVector('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:M/AR:L');
      expect(m).toBeTruthy();
      expect(m.CR).toBe('H');
      expect(m.IR).toBe('M');
      expect(m.AR).toBe('L');
    });

    it('should return null for invalid vector', () => {
      expect(MSAS.CVSS.parseVector('')).toBeNull();
      expect(MSAS.CVSS.parseVector(null)).toBeNull();
      expect(MSAS.CVSS.parseVector('CVSS:3.1/AV:N')).toBeNull(); // missing required metrics
    });

    it('should return null for non-string input', () => {
      expect(MSAS.CVSS.parseVector(123)).toBeNull();
      expect(MSAS.CVSS.parseVector(undefined)).toBeNull();
    });

    it('should handle CVSS 3.0 prefix', () => {
      const m = MSAS.CVSS.parseVector('CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(m).toBeTruthy();
      expect(m.AV).toBe('N');
    });
  });

  describe('baseScore', () => {
    it('should return 9.8 for remote code execution with full impact unchanged scope (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)', () => {
      const score = MSAS.CVSS.baseScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      });
      expect(score).toBeGreaterThanOrEqual(9.0);
      expect(score).toBeLessThanOrEqual(10.0);
    });

    it('should return ~8.6 for typical remote attack with some impact (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L)', () => {
      const score = MSAS.CVSS.baseScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'L'
      });
      expect(score).toBeGreaterThanOrEqual(7.0);
      expect(score).toBeLessThanOrEqual(9.0);
    });

    it('should return 10.0 for scope-changed full compromise (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)', () => {
      const score = MSAS.CVSS.baseScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'H'
      });
      // Per CVSS 3.1 spec, S:C with full CIA impact scores 10.0
      expect(score).toBe(10.0);
    });

    it('should return ~5.3 for local attack with medium impact (AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:L)', () => {
      const score = MSAS.CVSS.baseScore({
        AV: 'L', AC: 'L', PR: 'L', UI: 'R', S: 'U', C: 'L', I: 'L', A: 'L'
      });
      expect(score).toBeGreaterThanOrEqual(4.0);
      expect(score).toBeLessThanOrEqual(7.0);
    });

    it('should return 0 for no impact', () => {
      const score = MSAS.CVSS.baseScore({
        AV: 'P', AC: 'H', PR: 'H', UI: 'R', S: 'U', C: 'N', I: 'N', A: 'N'
      });
      expect(score).toBe(0);
    });

    it('should return 0 for null input', () => {
      expect(MSAS.CVSS.baseScore(null)).toBe(0);
    });
  });

  describe('Regression tests', () => {
    it('CVSS 3.1 S:C full-impact vector must score exactly 10.0 (regression: Bug#CVSS-SC)', () => {
      // Regression guard: the scope-changed Impact formula (7.52*(ISS-0.029)-3.25*(ISS-0.02)^15)
      // must produce 10.0 for AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H.
      // Previous buggy formula (1.08*ISS) returned ~5.3 instead of 10.0.
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBe(10.0);
    });
  });

  describe('Known CVSS vectors (reference values)', () => {
    // These are well-known CVSS 3.1 vectors with known base scores
    const testCases = [
      {
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        name: 'Full compromise unchanged scope',
        min: 9.0, max: 10.0
      },
      {
        vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        name: 'Full compromise with scope change',
        min: 10.0, max: 10.0
      },
      {
        vector: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
        name: 'High complexity limited impact',
        min: 4.0, max: 6.0
      },
      {
        vector: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N',
        name: 'Very difficult exploit',
        min: 1.0, max: 3.0
      },
    ];

    testCases.forEach(({ vector, name, min, max }) => {
      it(`should score "${name}" between ${min}-${max}`, () => {
        const result = MSAS.CVSS.score(vector);
        expect(result).toBeTruthy();
        expect(result.base).toBeGreaterThanOrEqual(min);
        expect(result.base).toBeLessThanOrEqual(max);
      });
    });
  });

  describe('Scope Changed (S:C) edge cases', () => {
    it('S:C with PR:L and full CIA impact should score ~9.9', () => {
      // AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeGreaterThanOrEqual(9.5);
      expect(result.base).toBeLessThanOrEqual(10.0);
      // S:C PR:L should score less than S:C PR:N (10.0) due to higher privileges
      const prNResult = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeLessThanOrEqual(prNResult.base);
    });

    it('S:C with PR:H and full CIA impact should score ~9.0', () => {
      // AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeGreaterThanOrEqual(8.0);
      expect(result.base).toBeLessThanOrEqual(10.0);
      // S:C PR:H should score less than S:C PR:L
      const prLResult = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeLessThanOrEqual(prLResult.base);
    });

    it('S:C with low CIA impacts (C:L/I:L/A:L) should score in medium range', () => {
      // AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L — S:C amplifies even low impacts
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L');
      expect(result.base).toBeGreaterThanOrEqual(7.0);
      expect(result.base).toBeLessThanOrEqual(9.5);
      
      // Same vector with S:U should score LOWER than S:C
      const sUResult = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L');
      expect(result.base).toBeGreaterThan(sUResult.base);
    });

    it('S:C with single CIA impact (C:H only) should score high', () => {
      // AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N — confidentiality only
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N');
      expect(result.base).toBeGreaterThanOrEqual(7.0);
      expect(result.base).toBeLessThanOrEqual(10.0);
    });

    it('S:C with physical attack vector should score lower than network', () => {
      // AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
      const result = MSAS.CVSS.score('CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeGreaterThanOrEqual(6.0);
      expect(result.base).toBeLessThanOrEqual(9.0);
      
      // Physical should score lower than Network for same metrics
      const netResult = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(result.base).toBeLessThan(netResult.base);
    });

    it('S:C with user interaction (UI:R) should score lower than UI:N', () => {
      // AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H — UI:R has lower exploitability (0.62 vs 0.85)
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H');
      expect(result.base).toBeGreaterThanOrEqual(8.0);
      expect(result.base).toBeLessThanOrEqual(10.0);
      
      // Same vector with UI:N (higher exploitability) should score >= UI:R
      const uiNResult = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(uiNResult.base).toBeGreaterThanOrEqual(result.base);
    });

    it('S:C with all low metrics should score higher than equivalent S:U', () => {
      // S:C with very restricted attack: AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L
      const sCResult = MSAS.CVSS.score('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L');
      
      // Same metrics with S:U
      const sUResult = MSAS.CVSS.score('CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L');
      
      // S:C should always score >= S:U for identical metrics
      expect(sCResult.base).toBeGreaterThanOrEqual(sUResult.base);
    });

    it('S:C temporal score should never exceed base score', () => {
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:T/RC:U');
      expect(result.temporal).toBeLessThanOrEqual(result.base);
      expect(result.temporal).toBeGreaterThanOrEqual(0);
    });

    it('S:C environmental score should produce valid range', () => {
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/CR:H/IR:H/AR:H');
      expect(result.environmental).toBeGreaterThanOrEqual(0);
      expect(result.environmental).toBeLessThanOrEqual(10);
    });

    it('S:C vs S:U scope amplification — more impactful metrics show larger gap', () => {
      // Low impact should have a smaller S:C vs S:U gap than high impact
      const lowCImpact = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N';
      const lowSCImpact = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N';
      const highCImpact = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N';
      const highSCImpact = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N';
      
      const lowGap = MSAS.CVSS.score(lowSCImpact).base - MSAS.CVSS.score(lowCImpact).base;
      const highGap = MSAS.CVSS.score(highSCImpact).base - MSAS.CVSS.score(highCImpact).base;
      
      // High impact should show a larger S:C amplification gap than low impact
      expect(highGap).toBeGreaterThanOrEqual(lowGap);
    });

    it('all S:C scores should be within valid CVSS range 0-10', () => {
      const vectors = [
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H',
        'CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H',
        'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:L/I:L/A:L',
        'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N',
        'CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L',
        'CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L',
        'CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:H/I:H/A:H',
      ];
      for (const v of vectors) {
        const result = MSAS.CVSS.score(v);
        expect(result.base).toBeGreaterThanOrEqual(0);
        expect(result.base).toBeLessThanOrEqual(10);
      }
    });
  });

  describe('temporalScore', () => {
    it('should reduce score when exploit code maturity and remediation level are favorable', () => {
      const base = MSAS.CVSS.baseScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      });
      const temporal = MSAS.CVSS.temporalScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
        E: 'U', RL: 'O', RC: 'C'
      });
      // Temporal should be <= base
      expect(temporal).toBeLessThanOrEqual(base);
    });

    it('should return 0 for null input', () => {
      expect(MSAS.CVSS.temporalScore(null)).toBe(0);
    });
  });

  describe('environmentalScore', () => {
    it('should adjust score based on security requirements', () => {
      const env = MSAS.CVSS.environmentalScore({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H',
        CR: 'H', IR: 'H', AR: 'H'
      });
      expect(env).toBeGreaterThanOrEqual(0);
      expect(env).toBeLessThanOrEqual(10);
    });

    it('should return 0 for null input', () => {
      expect(MSAS.CVSS.environmentalScore(null)).toBe(0);
    });
  });

  describe('score', () => {
    it('should return all three scores from a vector', () => {
      const result = MSAS.CVSS.score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
      expect(result).toBeTruthy();
      expect(result).toHaveProperty('vector');
      expect(result).toHaveProperty('base');
      expect(result).toHaveProperty('temporal');
      expect(result).toHaveProperty('environmental');
      expect(result).toHaveProperty('severity');
    });

    it('should return null for invalid vector', () => {
      expect(MSAS.CVSS.score('invalid')).toBeNull();
    });
  });

  describe('buildVector', () => {
    it('should build a valid CVSS vector from metrics', () => {
      const vector = MSAS.CVSS.buildVector({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H'
      });
      expect(vector).toContain('CVSS:3.1');
      expect(vector).toContain('AV:N');
      expect(vector).toContain('AC:L');
      expect(vector).toContain('C:H');
    });

    it('should produce a parsable vector', () => {
      const built = MSAS.CVSS.buildVector({
        AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'L', A: 'L'
      });
      const parsed = MSAS.CVSS.parseVector(built);
      expect(parsed).toBeTruthy();
      expect(parsed.AV).toBe('N');
      expect(parsed.C).toBe('H');
    });
  });

  describe('guessVector', () => {
    it('should return critical vector for critical severity', () => {
      const v = MSAS.CVSS.guessVector('critical');
      expect(v).toContain('AV:N');
      expect(v).toContain('C:H');
      expect(v).toContain('I:H');
    });

    it('should return info vector for info severity', () => {
      const v = MSAS.CVSS.guessVector('info');
      expect(v).toContain('AV:L');
      expect(v).toContain('C:N');
    });

    it('should return info vector for unknown severity', () => {
      const v = MSAS.CVSS.guessVector('unknown');
      expect(v).toContain('AV:L');
    });
  });

  describe('severityOf', () => {
    it('should return correct severity labels', () => {
      expect(MSAS.CVSS.severityOf(9.5)).toBe('critical');
      expect(MSAS.CVSS.severityOf(7.5)).toBe('high');
      expect(MSAS.CVSS.severityOf(5.0)).toBe('medium');
      expect(MSAS.CVSS.severityOf(2.0)).toBe('low');
      expect(MSAS.CVSS.severityOf(0.5)).toBe('info');
    });
  });

  describe('describeScore', () => {
    it('should return meaningful descriptions for each level', () => {
      expect(MSAS.CVSS.describeScore(9.5).length).toBeGreaterThan(0);
      expect(MSAS.CVSS.describeScore(7.5).length).toBeGreaterThan(0);
      expect(MSAS.CVSS.describeScore(5.0).length).toBeGreaterThan(0);
      expect(MSAS.CVSS.describeScore(2.0).length).toBeGreaterThan(0);
      expect(MSAS.CVSS.describeScore(0.5).length).toBeGreaterThan(0);
    });
  });

  describe('METRICS', () => {
    it('should expose all metric definitions', () => {
      expect(MSAS.CVSS.METRICS.base).toBeTruthy();
      expect(MSAS.CVSS.METRICS.temporal).toBeTruthy();
      expect(MSAS.CVSS.METRICS.environmental).toBeTruthy();
      expect(MSAS.CVSS.METRICS.modified).toBeTruthy();
      expect(MSAS.CVSS.METRICS.base.AV.values.N).toBe(0.85);
    });
  });
});
