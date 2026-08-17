import { defineConfig } from '@playwright/test';

const baseURL = process.env.HEADLAMP_URL || 'http://127.0.0.1:4466';

export default defineConfig({
  testDir: '.',
  testMatch: 'screenshots.spec.ts',
  timeout: 120_000,
  expect: { timeout: 45_000 },
  retries: 0,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL,
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
    screenshot: 'off',
    video: 'off',
    trace: 'off',
  },
});
