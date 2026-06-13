/**
 * mSAS v2 — E2E Tests: Landing Page
 * 
 * Tests for the home/index page: hero section, nav, tool cards, theme toggle, footer.
 */

import { test, expect } from '@playwright/test';

test.describe('Landing Page', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should load with correct page title and description', async ({ page }) => {
    await expect(page).toHaveTitle(/Mobile Security Analysis Suite/);
    const metaDesc = page.locator('meta[name="description"]');
    await expect(metaDesc).toHaveAttribute('content', /mobile security analysis/i);
  });

  test('should display hero section with title', async ({ page }) => {
    await expect(page.locator('h1')).toContainText('Mobile Security Analysis Suite');
    const hero = page.locator('.hero');
    await expect(hero).toBeVisible();
  });

  test('should display mSAS tagline badge', async ({ page }) => {
    const tag = page.locator('.hero-tag');
    await expect(tag).toContainText(/Android|iOS|security/i);
  });

  test('should display theme toggle button', async ({ page }) => {
    const themeBtn = page.locator('#themeToggle');
    await expect(themeBtn).toBeVisible();
    await expect(themeBtn).toHaveAttribute('aria-label', /theme/i);
  });

  test('should toggle theme between dark and light', async ({ page }) => {
    const themeBtn = page.locator('#themeToggle');
    const html = page.locator('html');
    
    // Start with dark theme
    await expect(html).toHaveAttribute('data-theme', 'dark');
    
    // Click to toggle to light
    await themeBtn.click();
    await expect(html).toHaveAttribute('data-theme', 'light');
    
    // Verify light theme persists in localStorage
    const theme = await page.evaluate(() => localStorage.getItem('theme'));
    expect(theme).toBe('light');
    
    // Toggle back to dark
    await themeBtn.click();
    await expect(html).toHaveAttribute('data-theme', 'dark');
    const themeDark = await page.evaluate(() => localStorage.getItem('theme'));
    expect(themeDark).toBe('dark');
  });

  test('should display all three tool cards (APK, IPA, ADB)', async ({ page }) => {
    const toolsGrid = page.locator('.tools-grid');
    await expect(toolsGrid).toBeVisible();
    
    const cards = page.locator('.tool-card');
    await expect(cards).toHaveCount(3);
    
    await expect(cards.nth(0)).toContainText('APK Auditor');
    await expect(cards.nth(1)).toContainText('IPA Auditor');
    await expect(cards.nth(2)).toContainText('ADB Auditor');
  });

  test('should navigate to APK auditor on card click', async ({ page }) => {
    await page.locator('.tool-card.apk .tool-card-cta').click();
    await expect(page).toHaveURL(/\/apk-auditor/);
    await expect(page.locator('h1')).toContainText(/Android/);
  });

  test('should navigate to IPA auditor on card click', async ({ page }) => {
    await page.locator('.tool-card.ipa .tool-card-cta').click();
    await expect(page).toHaveURL(/\/ipa-auditor/);
  });

  test('should navigate to ADB auditor on card click', async ({ page }) => {
    await page.locator('.tool-card.adb .tool-card-cta').click();
    await expect(page).toHaveURL(/\/adb-auditor/);
  });

  test('should have navigation bar with all tool links', async ({ page }) => {
    const navLinks = page.locator('.nav-links .nav-sibling');
    await expect(navLinks).toHaveCount(3);
    await expect(navLinks.nth(0)).toContainText('APK Auditor');
    await expect(navLinks.nth(1)).toContainText('IPA Auditor');
    await expect(navLinks.nth(2)).toContainText('ADB Auditor');
  });

  test('should navigate via navbar links', async ({ page }) => {
    await page.locator('.nav-links .nav-sibling').nth(0).click();
    await expect(page).toHaveURL(/\/apk-auditor/);
    
    await page.goBack();
    await page.locator('.nav-links .nav-sibling').nth(1).click();
    await expect(page).toHaveURL(/\/ipa-auditor/);
    
    await page.goBack();
    await page.locator('.nav-links .nav-sibling').nth(2).click();
    await expect(page).toHaveURL(/\/adb-auditor/);
  });

  test('should display CTA buttons (Analyze APK, Analyze IPA)', async ({ page }) => {
    const ctas = page.locator('.hero-cta');
    await expect(ctas).toBeVisible();
    await expect(ctas.locator('.btn-primary')).toContainText('Analyze APK');
    await expect(ctas.locator('.btn-pink')).toContainText('Analyze IPA');
  });

  test('should display hero features row', async ({ page }) => {
    const feats = page.locator('.hero-feats-row .hero-feat');
    await expect(feats).toHaveCount(5);
    await expect(feats.first()).toBeVisible();
  });

  test('should display footer with GitHub link', async ({ page }) => {
    const footer = page.locator('.site-footer');
    await expect(footer).toBeVisible();
    await expect(footer).toContainText('mSAS');
    await expect(footer.locator('a[href*="github"]').first()).toBeVisible();
    await expect(footer.locator('a[href*="github.com"]').first()).toBeVisible();
  });

  test('should have skip-to-content link', async ({ page }) => {
    const skip = page.locator('.skip-link');
    await expect(skip).toHaveText('Skip to content');
    await expect(skip).toHaveAttribute('href', '#main');
  });

  test('should have proper SEO meta tags', async ({ page }) => {
    const ogTitle = page.locator('meta[property="og:title"]');
    await expect(ogTitle).toHaveAttribute('content', /mSAS/);
    
    const robots = page.locator('meta[name="robots"]');
    await expect(robots).toHaveAttribute('content', 'index, follow');
  });

  test('should fetch API status endpoint', async ({ page }) => {
    const response = await page.request.get('/api/status');
    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(data.server).toContain('mSAS');
    expect(data.status).toBe('running');
  });

  test('should check API health endpoint', async ({ page }) => {
    const response = await page.request.get('/api/health');
    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(data.status).toBe('healthy');
  });

  test('should list tools via API', async ({ page }) => {
    const response = await page.request.get('/api/tools');
    expect(response.status()).toBe(200);
    const data = await response.json();
    expect(data.tools.length).toBeGreaterThanOrEqual(3);
    expect(data.tools.some(t => t.id === 'apk-auditor')).toBeTruthy();
    expect(data.tools.some(t => t.id === 'ipa-auditor')).toBeTruthy();
    expect(data.tools.some(t => t.id === 'adb-auditor')).toBeTruthy();
  });
});
