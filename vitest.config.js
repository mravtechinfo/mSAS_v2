import { defineConfig } from 'vitest/config';
import path from 'path';

export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./tests/setup.js'],
    include: ['./tests/**/*.test.js'],
    testTimeout: 10000,
    reporters: ['verbose'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['lib/**/*.js'],
      exclude: ['lib/scan-history.js', 'lib/dashboard.js', 'lib/dashboard-styles.css', 'lib/styles.css'],
    },
  },
  root: path.resolve(__dirname),
});
