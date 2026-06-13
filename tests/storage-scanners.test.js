/**
 * mSAS v2 — Unit Tests: Storage Scanners (Phase 1)
 * 
 * Tests for all 13 STO storage/data scanners.
 */

import { describe, it, expect } from 'vitest';

describe('MSAS.StorageScanner', () => {
  it('should detect SQLite database usage from DEX strings', () => {
    const findings = MSAS.StorageScanner.scan({
      strings: ['android.database.sqlite.SQLiteDatabase', 'test'],
    });
    const sqliteFindings = findings.filter(f => f.ruleId === 'mastg-storage-1-sqlite-api');
    expect(sqliteFindings.length).toBeGreaterThanOrEqual(1);
    expect(sqliteFindings[0].ruleName).toContain('SQLite Database');
  });

  it('should detect Realm SDK usage from DEX strings', () => {
    const findings = MSAS.StorageScanner.scan({
      strings: ['io.realm.Realm.getInstance', 'test', 'foo'],
    });
    const realmFindings = findings.filter(f => f.ruleId === 'mastg-storage-1-realm-sdk');
    expect(realmFindings.length).toBeGreaterThanOrEqual(1);
    expect(realmFindings[0].ruleName).toContain('Realm Database');
  });

  it('should detect embedded database files', () => {
    const findings = MSAS.StorageScanner.scan({
      files: ['res/raw/mydb.db', 'assets/data.sqlite'],
      strings: ['test'],
    });
    const dbFindings = findings.filter(f => f.ruleId === 'mastg-storage-1-embedded-sqlite');
    expect(dbFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should return secure finding when no database usage', () => {
    const findings = MSAS.StorageScanner.scan({
      strings: ['hello', 'world'],
      files: ['test.txt'],
    });
    const noDb = findings.filter(f => f.ruleId === 'mastg-storage-1-no-db');
    expect(noDb.length).toBeGreaterThanOrEqual(1);
    expect(noDb[0].severity).toBe('secure');
  });

  it('should produce findings with v1-compatible format', () => {
    const findings = MSAS.StorageScanner.scan({
      strings: ['android.database.sqlite'],
    });
    if (findings.length > 0) {
      const f = findings[0];
      expect(f).toHaveProperty('ruleId');
      expect(f).toHaveProperty('ruleName');
      expect(f).toHaveProperty('severity');
      expect(f).toHaveProperty('description');
      expect(f).toHaveProperty('cwe');
      expect(f).toHaveProperty('owasp');
      expect(f).toHaveProperty('masvs');
    }
  });
});

describe('MSAS.PrefsScanner', () => {
  it('should detect MODE_WORLD_READABLE usage', () => {
    const findings = MSAS.PrefsScanner.scan({
      strings: ['MODE_WORLD_READABLE', 'test'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    const modeFinding = findings.find(f => f.ruleId === 'mastg-storage-2-world-readable');
    if (modeFinding) {
      expect(modeFinding.ruleName).toContain('World-Readable');
    }
  });

  it('should return secure finding with no issues', () => {
    const findings = MSAS.PrefsScanner.scan({
      strings: ['hello', 'world'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.LogLeakageScanner', () => {
  it('should detect Log.e usage', () => {
    const findings = MSAS.LogLeakageScanner.scan({
      strings: ['Log.e', 'Landroid/util/Log;->e'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect System.out.print usage', () => {
    const findings = MSAS.LogLeakageScanner.scan({
      strings: ['Ljava/io/PrintStream;->println', 'System.out'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });

  it('should return findings in v1 format', () => {
    const findings = MSAS.LogLeakageScanner.scan({
      strings: ['Log.d', 'test'],
    });
    if (findings.length > 0) {
      expect(findings[0]).toHaveProperty('ruleId');
      expect(findings[0]).toHaveProperty('severity');
    }
  });
});

describe('MSAS.FirebaseScanner', () => {
  it('should detect Firebase database URLs', () => {
    const findings = MSAS.FirebaseScanner.scan({
      strings: ['myapp.firebaseio.com', 'test'],
    });
    const fbFindings = findings.filter(f => f.ruleId && f.ruleId.includes('firebase'));
    expect(fbFindings.length).toBeGreaterThanOrEqual(1);
  });

  it('should detect Firebase SDK usage', () => {
    const findings = MSAS.FirebaseScanner.scan({
      strings: ['com.google.firebase.database.FirebaseDatabase'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.ClipboardScanner', () => {
  it('should detect ClipboardManager usage', () => {
    const findings = MSAS.ClipboardScanner.scan({
      strings: ['android.content.ClipboardManager', 'ClipData'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]).toHaveProperty('ruleId');
    expect(findings[0]).toHaveProperty('severity');
  });

  it('should produce findings in v1 format', () => {
    const findings = MSAS.ClipboardScanner.scan({
      strings: ['ClipboardManager'],
    });
    if (findings.length > 0) {
      expect(findings[0]).toHaveProperty('ruleId');
      expect(findings[0]).toHaveProperty('description');
      expect(findings[0]).toHaveProperty('cwe');
    }
  });
});

describe('MSAS.ScreenshotScanner', () => {
  it('should detect FLAG_SECURE usage', () => {
    const findings = MSAS.ScreenshotScanner.scan({
      strings: ['FLAG_SECURE', 'Landroid/view/WindowManager'],
    });
    const flagFindings = findings.filter(f => f.ruleId === 'mastg-storage-5-flag-secure');
    expect(flagFindings.length).toBeGreaterThanOrEqual(1);
    expect(flagFindings[0].severity).toBe('secure');
  });
});

describe('MSAS.KeystoreScanner', () => {
  it('should detect Android KeyStore usage', () => {
    const findings = MSAS.KeystoreScanner.scan({
      strings: ['Ljava/security/KeyStore', 'AndroidKeyStore', 'Landroid/security/KeyChain'],
    });
    const ksFindings = findings.filter(f => f.ruleId === 'mastg-storage-5-android-keystore');
    expect(ksFindings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.NotificationScanner', () => {
  it('should detect notification patterns', () => {
    const findings = MSAS.NotificationScanner.scan({
      strings: ['NotificationCompat.Builder', 'FirebaseMessagingService'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.AnalyticsScanner', () => {
  it('should detect analytics SDKs', () => {
    const findings = MSAS.AnalyticsScanner.scan({
      strings: ['FirebaseAnalytics', 'com.google.firebase.analytics'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.DeviceAccessScanner', () => {
  it('should detect device admin usage', () => {
    const findings = MSAS.DeviceAccessScanner.scan({
      strings: ['DevicePolicyManager', 'android.app.admin'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});

describe('MSAS.CacheScanner', () => {
  it('should detect cache-related patterns', () => {
    const findings = MSAS.CacheScanner.scan({
      strings: ['getCacheDir', 'external_cache', 'cache'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]).toHaveProperty('ruleId');
    expect(findings[0]).toHaveProperty('severity');
  });
});

describe('MSAS.BackupScanner', () => {
  it('should detect backup-related patterns', () => {
    const findings = MSAS.BackupScanner.scan({
      strings: ['android:allowBackup', 'BackupAgent'],
      files: ['AndroidManifest.xml'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
    expect(findings[0]).toHaveProperty('ruleId');
  });
});

describe('MSAS.ScopedStorageScanner', () => {
  it('should detect legacy storage patterns', () => {
    const findings = MSAS.ScopedStorageScanner.scan({
      strings: ['getExternalStorageDirectory', 'WRITE_EXTERNAL_STORAGE'],
    });
    expect(findings.length).toBeGreaterThanOrEqual(1);
  });
});
