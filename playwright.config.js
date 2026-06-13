import { defineConfig } from '@playwright/test';

const BASE_URL = process.env.BASE_URL || 'http://localhost:8080';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  retries: 1,
  workers: 1,
  timeout: 30000,
  expect: {
    timeout: 10000,
  },
  use: {
    baseURL: BASE_URL,
    headless: true,
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
    trace: 'retain-on-failure',
    actionTimeout: 10000,
    navigationTimeout: 15000,
  },
  projects: [
    {
      name: 'chromium',
      use: {
        browserName: 'chromium',
        viewport: { width: 1280, height: 800 },
      },
    },
  ],
  // Server started manually via `python3 server.py 8080` from the project root.
  // The webServer config is omitted to avoid port conflicts with the manually
  // started server. Set BASE_URL to use a different server URL.
  reporter: [
    ['list'],
  ],
});
