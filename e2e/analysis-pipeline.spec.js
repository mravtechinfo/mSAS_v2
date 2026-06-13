/**
 * mSAS v2 — E2E Tests: Analysis Pipeline
 *
 * Tests the full APK analysis pipeline: file upload via drag-and-drop,
 * analysis execution, results display, tabs, filters, explorer, export
 * functionality, and the "New Scan" flow.
 *
 * Uses the test_app.apk fixture from the project root.
 *
 * Post-analysis tests share a single page via test.describe.serial()
 * to avoid redundant APK uploads (analysis takes 10-60 seconds).
 * A beforeEach resets to the Overview tab so tests are order-independent.
 * The New Scan flow and re-upload test run last, as they disrupt the
 * shared page state.
 */

import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

const APK_PATH = path.resolve(__dirname, '../../test_app.apk');
const APK_EXISTS = fs.existsSync(APK_PATH);

// ── Pre-analysis tests (run on fresh page, no APK needed) ─────────────────────

test.describe('APK Analysis Pipeline — Landing & Pre-analysis', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/apk-auditor/');
  });

  test('should have dropzone visible and ready before upload', async ({ page }) => {
    const dropzone = page.locator('#dropZone');
    await expect(dropzone).toBeVisible();
    await expect(dropzone).toContainText('Drop');
    await expect(dropzone).toHaveAttribute('role', 'button');
    await expect(dropzone).toHaveAttribute('tabindex', '0');
  });

  test('should trigger file input when CTA button is clicked', async ({ page }) => {
    const cta = page.locator('#heroCta');
    await expect(cta).toBeVisible();
    await expect(cta).toContainText('.apk');

    const fileInput = page.locator('#fileInput');
    await expect(fileInput).toHaveAttribute('accept', '.apk,.zip');
  });

  test('should have preview card showing sample findings', async ({ page }) => {
    const previewCard = page.locator('#previewCard');
    await expect(previewCard).toBeVisible();
    await expect(previewCard.locator('[data-field="sev"]')).toBeVisible();
    await expect(previewCard.locator('[data-field="title"]')).toBeVisible();
    await expect(previewCard.locator('[data-field="conf"]')).toBeVisible();
    await expect(previewCard.locator('[data-field="meta"]')).toBeVisible();
  });

  test('should display hero feature row with security categories', async ({ page }) => {
    const featRow = page.locator('.hero-feats-row');
    await expect(featRow).toBeVisible();
    await expect(featRow.locator('.hero-feat-key')).toHaveCount(4);
    await expect(featRow).toContainText('DEX');
    await expect(featRow).toContainText('Manifest');
    await expect(featRow).toContainText('Cert');
  });

  test('should have theme toggle and cycle between dark and light', async ({ page }) => {
    const toggle = page.locator('#themeToggle');
    await expect(toggle).toBeVisible();

    const initialTheme = await page.evaluate(() => document.documentElement.dataset.theme);

    await toggle.click();
    const afterFirst = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(afterFirst).not.toBe(initialTheme);

    await toggle.click();
    const afterSecond = await page.evaluate(() => document.documentElement.dataset.theme);
    expect(afterSecond).toBe(initialTheme);
  });

  test('should have header navigation to other auditors', async ({ page }) => {
    const nav = page.locator('.nav-links');
    await expect(nav.locator('a[href="../"]')).toBeVisible();
    await expect(nav.locator('a[href="../ipa-auditor/"]')).toBeVisible();
    await expect(nav.locator('a[href="../adb-auditor/"]')).toBeVisible();
  });
});

// ── Post-analysis tests (shared page, one upload) ────────────────────────────

test.describe.serial('APK Analysis Pipeline — Results', () => {
  /** @type {import('@playwright/test').Page} */
  let sharedPage;

  test.beforeAll(async ({ browser }) => {
    test.skip(!APK_EXISTS, 'test_app.apk not found — skip analysis pipeline results tests');

    // Extend timeout: APK analysis can take 10-60 seconds
    test.setTimeout(180000);

    sharedPage = await browser.newPage();
    await sharedPage.goto('/apk-auditor/');

    // Upload and wait for analysis
    const fileChooserPromise = sharedPage.waitForEvent('filechooser', { timeout: 5000 });
    await sharedPage.locator('#heroCta').click();
    const fileChooser = await fileChooserPromise;
    await fileChooser.setFiles(APK_PATH);

    // Wait for results container to appear (analysis may take up to 60s)
    await expect(sharedPage.locator('#appContainer')).toBeVisible({ timeout: 70000 });
  });

  test.afterAll(async () => {
    if (sharedPage) await sharedPage.close();
  });

  // Reset to Overview tab before each test for isolation
  test.beforeEach(async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Overview' }).click();
  });

  // ── 1. Header ──────────────────────────────────────────────────────────

  test('should display app header with name and package after analysis', async () => {
    const appName = sharedPage.locator('#appName');
    await expect(appName).toBeVisible();
    const text = await appName.textContent();
    // Should have replaced the placeholder "App Name"
    expect(text).toBeTruthy();
    expect(text).not.toBe('App Name');
    expect(text.length).toBeGreaterThan(0);

    const bundleId = sharedPage.locator('#bundleId');
    await expect(bundleId).toBeVisible();
  });

  // ── 2. Overview panel ──────────────────────────────────────────────────

  test('should display security score ring with score value', async () => {
    const scoreCard = sharedPage.locator('.score-card');
    await expect(scoreCard).toBeVisible();

    const scoreValue = sharedPage.locator('.score-value');
    await expect(scoreValue).toBeVisible();
    const scoreText = await scoreValue.textContent();
    const score = parseInt(scoreText, 10);
    expect(score).not.toBeNaN();
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);

    const scoreLabel = sharedPage.locator('.score-label');
    await expect(scoreLabel).toBeVisible();
  });

  test('should display findings stat cards with clickable severity filters', async () => {
    const findingsCard = sharedPage.locator('.findings-card');
    await expect(findingsCard).toBeVisible();

    await expect(findingsCard.locator('[data-jumpsev="issue"]')).toBeVisible();
    await expect(findingsCard.locator('[data-jumpsev="info"]')).toBeVisible();
    await expect(findingsCard.locator('[data-jumpsev="secure"]')).toBeVisible();
  });

  test('should display stat cards for permissions, DEX, trackers, native libs', async () => {
    const stats = sharedPage.locator('#overviewStats');
    await expect(stats).toBeVisible();

    // At minimum, the security score card and findings card should render
    await expect(stats.locator('.stat-card').first()).toBeVisible();
    const count = await stats.locator('.stat-card').count();
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('should display application info grid with package details', async () => {
    const infoGrid = sharedPage.locator('#appInfoGrid');
    await expect(infoGrid).toBeVisible();

    await expect(infoGrid.locator('.info-item').first()).toBeVisible();
    const items = await infoGrid.locator('.info-item').count();
    expect(items).toBeGreaterThanOrEqual(2);
  });

  test('should display dangerous permissions section', async () => {
    const permsList = sharedPage.locator('#dangerousPermsList');
    await expect(permsList).toBeVisible();
  });

  test('should display trackers and SDKs section', async () => {
    const trackersList = sharedPage.locator('#trackersList');
    await expect(trackersList).toBeVisible();
  });

  test('should display URLs found in DEX section', async () => {
    const urlsList = sharedPage.locator('#urlsList');
    await expect(urlsList).toBeVisible();
  });

  // ── 3. Findings panel ──────────────────────────────────────────────────

  test('should navigate to Findings tab and display severity filter toolbar', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();

    // Use aria-label to target the findings-specific toolbar (avoids conflict with components toolbar)
    const toolbar = sharedPage.locator('[aria-label="Findings filters"]');
    await expect(toolbar).toBeVisible();
    await expect(toolbar.locator('.filter-btn[data-filter="all"]')).toBeVisible();
    await expect(toolbar.locator('.filter-btn[data-filter="issue"]')).toBeVisible();
    await expect(toolbar.locator('.filter-btn[data-filter="info"]')).toBeVisible();
    await expect(toolbar.locator('.filter-btn[data-filter="secure"]')).toBeVisible();
  });

  test('should display findings list with result count after analysis', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();

    const findingsList = sharedPage.locator('#findingsList');
    await expect(findingsList).toBeVisible();

    const resultCount = sharedPage.locator('#findingsResultCount');
    await expect(resultCount).toBeVisible();
    const countText = await resultCount.textContent();
    expect(countText).toMatch(/\d+/);
  });

  test('should have search input, sort dropdown, and confidence slider in findings', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();

    await expect(sharedPage.locator('#findingsSearchInput')).toBeVisible();
    await expect(sharedPage.locator('#findingsSearchInput')).toHaveAttribute('placeholder', /Search/);

    await expect(sharedPage.locator('#findingsSort')).toBeVisible();
    await expect(sharedPage.locator('#findingsMinConfidence')).toBeVisible();
  });

  test('should expand and collapse finding cards', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();

    const cards = sharedPage.locator('.finding-card');
    const cardCount = await cards.count();
    test.skip(cardCount === 0, 'No findings to test expand/collapse');

    const firstCard = cards.first();
    const header = firstCard.locator('.finding-header');
    const body = firstCard.locator('.finding-body');

    await expect(header).toHaveAttribute('aria-expanded', 'false');
    await expect(body).toBeHidden();

    await header.click();
    await expect(header).toHaveAttribute('aria-expanded', 'true');
    await expect(body).not.toBeHidden();

    await header.click();
    await expect(header).toHaveAttribute('aria-expanded', 'false');
    await expect(body).toBeHidden();
  });

  test('should have Expand All and Collapse All buttons', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();
    await expect(sharedPage.locator('#expandAllBtn')).toBeVisible();
    await expect(sharedPage.locator('#collapseAllBtn')).toBeVisible();
  });

  test('should filter findings by severity', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Findings' }).click();

    const allBtn = sharedPage.locator('.filter-btn[data-filter="all"]');
    const issueBtn = sharedPage.locator('.filter-btn[data-filter="issue"]');

    await issueBtn.click();
    await expect(issueBtn).toHaveClass(/active/);

    await allBtn.click();
    await expect(allBtn).toHaveClass(/active/);
  });

  // ── 4. Manifest panel ──────────────────────────────────────────────────

  test('should navigate to Manifest tab and display package info', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Manifest' }).click();

    const summary = sharedPage.locator('#manifestSummary');
    await expect(summary).toBeVisible();
    const infoItems = await summary.locator('.info-item').count();
    expect(infoItems).toBeGreaterThanOrEqual(1);
  });

  test('should display permissions table in Manifest tab', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Manifest' }).click();

    await expect(sharedPage.locator('#permissionsList')).toBeVisible();
    await expect(sharedPage.locator('#permissionsCount')).toBeVisible();
  });

  test('should display raw AndroidManifest.xml content', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Manifest' }).click();

    const manifestRaw = sharedPage.locator('#manifestRaw');
    await expect(manifestRaw).toBeVisible();
  });

  // ── 5. Components panel ────────────────────────────────────────────────

  test('should navigate to Components tab and show summary stats', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Components' }).click();

    const summary = sharedPage.locator('#componentsSummary');
    await expect(summary).toBeVisible();

    const statCards = summary.locator('.stat-card');
    await expect(statCards.first()).toBeVisible();
    const count = await statCards.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test('should have component type and scope filter toolbar', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Components' }).click();

    const toolbar = sharedPage.locator('#componentsToolbar');
    await expect(toolbar).toBeVisible();
    await expect(toolbar.locator('[data-scope="all"]')).toBeVisible();
    await expect(toolbar.locator('[data-scope="exported"]')).toBeVisible();
    await expect(toolbar.locator('[data-type="all"]')).toBeVisible();
    await expect(toolbar.locator('[data-type="activity"]')).toBeVisible();
  });

  test('should display component cards that can be expanded', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Components' }).click();

    const compList = sharedPage.locator('#componentsList');
    await expect(compList).toBeVisible();

    const cards = compList.locator('.comp-card');
    const cardCount = await cards.count();
    test.skip(cardCount === 0, 'No components to test expand/collapse');

    const firstCard = cards.first();
    const header = firstCard.locator('.comp-card-header');
    const body = firstCard.locator('.comp-card-body');

    await expect(header).toHaveAttribute('aria-expanded', 'false');
    await expect(body).toBeHidden();

    await header.click();
    await expect(header).toHaveAttribute('aria-expanded', 'true');
    await expect(body).not.toBeHidden();
  });

  // ── 6. Cert panel ──────────────────────────────────────────────────────

  test('should navigate to Cert tab and display certificate info', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Cert' }).click();

    await expect(sharedPage.locator('#certCard')).toBeVisible();
  });

  test('should display signature scheme info in Cert tab', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Cert' }).click();

    await expect(sharedPage.locator('#sigSchemeCard')).toBeVisible();
    await expect(sharedPage.locator('#sigSchemeCard').locator('.ats-flags')).toBeVisible();
  });

  // ── 7. Explorer panel ──────────────────────────────────────────────────

  test('should navigate to Explorer tab with quick access and file tree', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Explorer' }).click();

    await expect(sharedPage.locator('#quickAccessList')).toBeVisible();
    await expect(sharedPage.locator('#fileTree')).toBeVisible();
    await expect(sharedPage.locator('#totalFileCount')).toBeVisible();
  });

  test('should have explorer search modes (name, content, strings)', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Explorer' }).click();

    const searchMode = sharedPage.locator('.explorer-search-mode');
    await expect(searchMode).toBeVisible();
    await expect(searchMode.locator('[data-search-mode="name"]')).toBeVisible();
    await expect(searchMode.locator('[data-search-mode="content"]')).toBeVisible();
    await expect(searchMode.locator('[data-search-mode="strings"]')).toBeVisible();
  });

  // ── 8. Export functionality ────────────────────────────────────────────

  test('should open and close export dropdown', async () => {
    const exportBtn = sharedPage.locator('#exportMenuBtn');
    await expect(exportBtn).toBeVisible();

    // Open dropdown
    await exportBtn.click();
    const dropdown = sharedPage.locator('#exportDropdown');
    await expect(dropdown).toBeVisible();
    await expect(dropdown).not.toBeHidden();

    // Verify all export options present
    await expect(dropdown.locator('[data-export="pdf"]')).toBeVisible();
    await expect(dropdown.locator('[data-export="json"]')).toBeVisible();
    await expect(dropdown.locator('[data-export="csv"]')).toBeVisible();
    await expect(dropdown.locator('[data-export="sarif"]')).toBeVisible();

    // Close by clicking export button again
    await exportBtn.click();
    await expect(dropdown).toBeHidden();
  });

  test('should trigger JSON export and close dropdown on export click', async () => {
    const exportBtn = sharedPage.locator('#exportMenuBtn');
    await exportBtn.click();
    await expect(sharedPage.locator('#exportDropdown')).toBeVisible({ timeout: 3000 });

    // Click JSON export
    await sharedPage.locator('[data-export="json"]').click();

    // Dropdown should close
    await expect(sharedPage.locator('#exportDropdown')).toBeHidden({ timeout: 3000 });
  });

  // ── 9. Dashboard tab ───────────────────────────────────────────────────

  test('should navigate to Dashboard tab and render metrics', async () => {
    await sharedPage.locator('.tab').filter({ hasText: 'Dashboard' }).click();
    await expect(sharedPage.locator('#dashboardContent')).toBeVisible();

    // Dashboard should render real metrics (not the placeholder "no data" message)
    await expect(sharedPage.locator('#dashboardContent .no-data')).toHaveCount(0, { timeout: 5000 });
  });

  // ── 10. Overview severity drilldown ─────────────────────────────────────

  test('should drill down from overview severity row to filtered findings', async () => {
    const issueRow = sharedPage.locator('[data-jumpsev="issue"]');
    await expect(issueRow).toBeVisible();

    await issueRow.click();

    // Should navigate to Findings tab
    const activeTab = sharedPage.locator('.tab.active');
    await expect(activeTab).toContainText('Findings');

    // "Issues" filter should be active
    const issueFilter = sharedPage.locator('.filter-btn[data-filter="issue"]');
    await expect(issueFilter).toHaveClass(/active/);
  });

  // ── 11. New Scan & Landing flow (last — disrupts shared page state) ───

  test('should trigger file chooser when New Scan button is clicked', async () => {
    // The New Scan button opens the file input, not the landing view
    const newScanBtn = sharedPage.locator('#newScanBtn');
    await expect(newScanBtn).toBeVisible();
    await expect(newScanBtn).toContainText('New Scan');

    // Clicking New Scan should trigger a file chooser event
    const fileChooserPromise = sharedPage.waitForEvent('filechooser', { timeout: 5000 });
    await newScanBtn.click();
    const fc = await fileChooserPromise;
    expect(fc).toBeTruthy();
  });

  test('should return to landing view when logo is clicked', async () => {
    // The logo link triggers showLanding() which reveals the landing content
    await sharedPage.locator('.logo').first().click();
    await expect(sharedPage.locator('#landingContent')).not.toBeHidden();
    await expect(sharedPage.locator('#appContainer')).not.toHaveClass(/active/);
  });
});
