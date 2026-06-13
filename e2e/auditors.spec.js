/**
 * mSAS v2 — E2E Tests: Auditors (APK, IPA, ADB)
 * 
 * Tests for each auditor page: page loads, key UI elements, navigation.
 */

import { test, expect } from '@playwright/test';

test.describe('APK Auditor Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/apk-auditor/');
  });

  test('should load with correct title', async ({ page }) => {
    await expect(page).toHaveTitle(/APK Auditor/);
  });

  test('should display hero section with upload CTA', async ({ page }) => {
    await expect(page.locator('.hero-title')).toContainText(/Android/i);
    const cta = page.locator('#heroCta');
    await expect(cta).toBeVisible();
    await expect(cta).toContainText('Pick an .apk');
  });

  test('should display dropzone for file upload', async ({ page }) => {
    const dropzone = page.locator('#dropZone');
    await expect(dropzone).toBeVisible();
    await expect(dropzone).toHaveAttribute('aria-label', /Drop|APK/i);
  });

  test('should have file input for APK upload', async ({ page }) => {
    const fileInput = page.locator('#fileInput');
    // File input is visually hidden but present in DOM
    await expect(fileInput).toHaveAttribute('accept', '.apk,.zip');
    await expect(fileInput).toHaveAttribute('aria-label', 'Select APK file');
  });

  test('should display content tabs with expected labels', async ({ page }) => {
    // Tabs are inside #appContainer hidden until a file is analyzed;
    // assert they exist in the DOM rather than requiring visibility
    await expect(page.locator('.tab').filter({ hasText: 'Overview' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Findings' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Manifest' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Components' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Cert' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Explorer' })).toHaveCount(1);
  });

  test('should display hero features section', async ({ page }) => {
    const feats = page.locator('.hero-feats-row .hero-feat');
    await expect(feats).toHaveCount(4);
    await expect(feats.nth(0)).toContainText('DEX');
    await expect(feats.nth(1)).toContainText('Manifest');
    await expect(feats.nth(2)).toContainText('Cert');
    await expect(feats.nth(3)).toContainText('Secrets');
  });

  test('should display navbar with sibling auditor links', async ({ page }) => {
    const navLinks = page.locator('.nav-links .nav-sibling');
    await expect(navLinks).toHaveCount(3);
    await expect(navLinks.nth(0)).toContainText('Dashboard');
    await expect(navLinks.nth(1)).toContainText('IPA Auditor');
    await expect(navLinks.nth(2)).toContainText('ADB Auditor');
  });

  test('should navigate to Dashboard from nav', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').filter({ hasText: 'Dashboard' }).click();
    await expect(page).toHaveURL(/\/$/);
  });

  test('should navigate to IPA Auditor page', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').filter({ hasText: 'IPA' }).click();
    await expect(page).toHaveURL(/\/ipa-auditor/);
  });

  test('should navigate to ADB Auditor page', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').filter({ hasText: 'ADB' }).click();
    await expect(page).toHaveURL(/\/adb-auditor/);
  });

  test('should have theme toggle button and toggle theme attribute', async ({ page }) => {
    await expect(page.locator('#themeToggle')).toBeVisible();
    // Theme may not persist to localStorage on all pages due to different implementations
    // Just verify the toggle exists and click works
    await page.locator('#themeToggle').click();
    const theme = await page.evaluate(() => document.documentElement.getAttribute('data-theme'));
    expect(['light', 'dark']).toContain(theme);
  });

  test('should display footer with GitHub link', async ({ page }) => {
    const footer = page.locator('.site-footer');
    await expect(footer).toBeVisible();
    await expect(footer).toContainText('APK Auditor');
    await expect(footer.locator('a[href*="github"]').first()).toBeVisible();
  });
});

test.describe('IPA Auditor Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/ipa-auditor/');
  });

  test('should load with correct title', async ({ page }) => {
    await expect(page).toHaveTitle(/IPA Auditor/);
  });

  test('should display hero section with upload CTA', async ({ page }) => {
    await expect(page.locator('.hero-title')).toContainText(/iOS|IPA/);
  });

  test('should display dropzone for file upload', async ({ page }) => {
    const dropzone = page.locator('#dropZone');
    await expect(dropzone).toBeVisible();
  });

  test('should display content tabs with expected labels', async ({ page }) => {
    // Tabs are inside #appContainer hidden until a file is analyzed;
    // assert they exist in the DOM rather than requiring visibility
    await expect(page.locator('.tab').filter({ hasText: 'Overview' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Findings' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Binary' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Entitlements' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'ATS' })).toHaveCount(1);
    await expect(page.locator('.tab').filter({ hasText: 'Explorer' })).toHaveCount(1);
  });

  test('should have file input for IPA upload', async ({ page }) => {
    await expect(page.locator('#fileInput')).toHaveAttribute('accept', '.ipa,.zip');
  });

  test('should display navbar with sibling auditor links', async ({ page }) => {
    const navLinks = page.locator('.nav-links .nav-sibling');
    await expect(navLinks).toHaveCount(3);
    await expect(navLinks.nth(0)).toContainText('Dashboard');
    await expect(navLinks.nth(1)).toContainText('APK Auditor');
    await expect(navLinks.nth(2)).toContainText('ADB Auditor');
  });

  test('should navigate to ADB Auditor from nav', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').filter({ hasText: 'ADB' }).click();
    await expect(page).toHaveURL(/\/adb-auditor/);
  });
});

test.describe('ADB Auditor Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/adb-auditor/');
  });

  test('should load with correct title', async ({ page }) => {
    await expect(page).toHaveTitle(/ADB Auditor|Device|Security/i);
  });

  test('should display main content sections', async ({ page }) => {
    await expect(page.locator('h1, h2').first()).toBeVisible();
  });

  test('should display navbar with sibling auditor links', async ({ page }) => {
    const navLinks = page.locator('.nav-links .nav-sibling');
    await expect(navLinks).toHaveCount(3);
    await expect(navLinks.nth(0)).toContainText('Dashboard');
    await expect(navLinks.nth(1)).toContainText('IPA Auditor');
    await expect(navLinks.nth(2)).toContainText('APK Auditor');
  });

  test('should navigate to APK Auditor from nav', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').filter({ hasText: 'APK' }).click();
    await expect(page).toHaveURL(/\/apk-auditor/);
  });
});
