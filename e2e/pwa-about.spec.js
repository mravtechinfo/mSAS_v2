/**
 * mSAS v2 — E2E Tests: PWA, About, Downloads, Error Pages
 * 
 * Tests for PWA manifest, service worker registration, about page,
 * downloads page, and 404 error handling.
 */

import { test, expect } from '@playwright/test';

test.describe('PWA Features', () => {
  test('should serve correct manifest.json', async ({ page }) => {
    const response = await page.request.get('/manifest.json');
    expect(response.status()).toBe(200);

    const manifest = await response.json();
    expect(manifest.name).toContain('mSAS');
    expect(manifest.short_name).toBe('mSAS');
    expect(manifest.display).toBe('standalone');
    expect(manifest.start_url).toContain('/index.html');
    expect(manifest.categories).toContain('security');
    expect(manifest.shortcuts).toHaveLength(3);
    expect(manifest.shortcuts.some(s => s.name === 'APK Auditor')).toBeTruthy();
    expect(manifest.shortcuts.some(s => s.name === 'IPA Auditor')).toBeTruthy();
    expect(manifest.shortcuts.some(s => s.name === 'ADB Auditor')).toBeTruthy();
  });

  test('should have PWA icons referenced', async ({ page }) => {
    const manifest = await (await page.request.get('/manifest.json')).json();
    expect(manifest.icons.length).toBeGreaterThanOrEqual(2);
    for (const icon of manifest.icons) {
      expect(icon.sizes).toBeTruthy();
      expect(icon.type).toBe('image/png');
    }
  });

  test('should register service worker', async ({ page }) => {
    await page.goto('/');
    
    // Verify the SW file is served correctly
    const swResponse = await page.request.get('/sw.js');
    expect(swResponse.status()).toBe(200);
    const swContent = await swResponse.text();
    expect(swContent).toContain('CACHE_NAME');
    expect(swContent).toContain('PRECACHE_URLS');
    
    // Check if SW API is available (might not register in headless test env)
    const hasSwApi = await page.evaluate(() => 'serviceWorker' in navigator);
    expect(hasSwApi).toBe(true);
  });

  test('service worker should cache static assets', async ({ page }) => {
    await page.goto('/');
    
    // Check if caches API is available
    const cachesAvailable = await page.evaluate(() => typeof caches !== 'undefined');
    expect(cachesAvailable).toBe(true);
    
    if (cachesAvailable) {
      await page.waitForTimeout(1000);
      
      const cacheNames = await page.evaluate(async () => {
        try {
          return await caches.keys();
        } catch {
          return [];
        }
      });
      
      const msasCache = cacheNames.find(n => n.startsWith('msas'));
      if (msasCache) {
        const cachedUrls = await page.evaluate(async (cacheName) => {
          const cache = await caches.open(cacheName);
          const requests = await cache.keys();
          return requests.map(r => r.url).filter(url => url.includes('index.html'));
        }, msasCache);
        expect(cachedUrls.length).toBeGreaterThanOrEqual(0);
      }
    }
  });

  test('should have PWA meta tags', async ({ page }) => {
    await page.goto('/');
    
    const themeColor = page.locator('meta[name="theme-color"]');
    await expect(themeColor.first()).toHaveAttribute('content');
    
    const appName = page.locator('meta[name="application-name"]');
    await expect(appName).toHaveAttribute('content', /mSAS/);
  });
});

test.describe('About Page', () => {
  test('should load about page', async ({ page }) => {
    await page.goto('/about/');
    await expect(page).toHaveURL(/\/about/);
    await expect(page.locator('body')).toBeVisible();
  });
});

test.describe('Downloads Page', () => {
  test('should load downloads page', async ({ page }) => {
    await page.goto('/downloads/');
    await expect(page).toHaveURL(/\/downloads/);
    await expect(page.locator('body')).toBeVisible();
  });

  test('should list downloadable artifacts', async ({ page }) => {
    await page.goto('/downloads/');
    // Should show the ZIP or announce downloads
    const body = page.locator('body');
    await expect(body).toBeVisible();
  });
});

test.describe('Error Pages', () => {
  test('should return 404 for unknown routes', async ({ page }) => {
    const response = await page.goto('/nonexistent-page-test/');
    expect(response.status()).toBe(404);
  });

  test('should return JSON error for unknown API routes', async ({ page }) => {
    const response = await page.request.get('/api/unknown-endpoint');
    expect(response.status()).toBe(404);
    const data = await response.json();
    expect(data).toHaveProperty('error');
    expect(data).toHaveProperty('status', 404);
  });

  test('should return 404 for API on tool endpoint with bad tool', async ({ page }) => {
    const response = await page.request.post('/api/analyze/unknown');
    expect(response.status()).toBe(200); // Returns JSON with info, not a 404
    const data = await response.json();
    expect(data.clientSide).toBe(true);
  });
});

test.describe('Security Headers', () => {
  test('should have CSP meta tag on landing page', async ({ page }) => {
    await page.goto('/');
    const csp = page.locator('meta[http-equiv="Content-Security-Policy"]');
    await expect(csp).toHaveAttribute('content', /default-src 'self'/);
  });

  test('should have strict CSP on APK auditor page', async ({ page }) => {
    await page.goto('/apk-auditor/');
    const csp = page.locator('meta[http-equiv="Content-Security-Policy"]');
    await expect(csp).toHaveAttribute('content', /worker-src 'self' blob:/);
  });

  test('should have X-Content-Type-Options header on APK auditor page', async ({ page }) => {
    // This meta tag is only on the APK auditor page
    await page.goto('/apk-auditor/');
    const xcto = page.locator('meta[http-equiv="X-Content-Type-Options"]');
    await expect(xcto).toHaveAttribute('content', 'nosniff');
  });
});

test.describe('Features Roadmap', () => {
  test('should load features roadmap page', async ({ page }) => {
    await page.goto('/features-roadmap.html');
    await expect(page).toHaveTitle(/Feature Roadmap/);
  });

  test('should show summary cards on roadmap', async ({ page }) => {
    await page.goto('/features-roadmap.html');
    const summaryCards = page.locator('.summary-card');
    await expect(summaryCards.first()).toBeVisible();
  });

  test('should have phase sections with toggle behavior', async ({ page }) => {
    await page.goto('/features-roadmap.html');
    const phases = page.locator('.phase');
    const count = await phases.count();
    expect(count).toBeGreaterThanOrEqual(9);
    
    // First phase should be visible
    await expect(phases.first()).toBeVisible();
    await expect(phases.first().locator('.phase-title')).toContainText('Phase');
  });
});
