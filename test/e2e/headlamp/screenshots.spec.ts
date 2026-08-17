import { expect, test, type Page } from '@playwright/test';
import * as fs from 'node:fs';
import * as path from 'node:path';

test.use({
  baseURL: process.env.HEADLAMP_URL || 'http://127.0.0.1:4466',
  viewport: { width: 1440, height: 900 },
  ignoreHTTPSErrors: true,
});
test.setTimeout(180_000);

const cluster = process.env.HEADLAMP_CLUSTER || 'main';
const wafNS = process.env.WAF_NS || 'demo';
const wafName = process.env.WAF_NAME || 'demo-waf-eg-path-b';
const rulesetName = process.env.RULESET_NAME || 'ftw-crs-path-b';
const shotDir =
  process.env.HEADLAMP_SCREENSHOT_DIR || path.join(__dirname, 'artifacts');

function clusterPath(p: string): string {
  const trimmed = p.startsWith('/') ? p : `/${p}`;
  return `/c/${cluster}${trimmed}`;
}

async function shot(page: Page, name: string) {
  fs.mkdirSync(shotDir, { recursive: true });
  const dest = path.join(shotDir, name);
  await page.screenshot({ path: dest, fullPage: true });
  const st = fs.statSync(dest);
  expect(st.size, `${name} should not be empty`).toBeGreaterThan(8_000);
}

async function gotoKubeWAF(page: Page, route: string) {
  await page.goto(clusterPath(route), { waitUntil: 'domcontentloaded' });
  // In-cluster token skip should land on the cluster; if a login form still
  // appears, fail with a useful screenshot rather than hanging.
  const login = page.getByRole('button', { name: /authenticate|log in|next/i });
  if (await login.isVisible({ timeout: 2_000 }).catch(() => false)) {
    await shot(page, '00-unexpected-login.png');
    throw new Error('Headlamp showed a login form; unsafeUseServiceAccountToken is off');
  }
  await expect(page.getByText(/kubeWAF/i).first()).toBeVisible({ timeout: 45_000 });
}

test.describe('kubeWAF Headlamp Path B CRS', () => {
  test('plugin is loaded', async ({ request }) => {
    const res = await request.get('/plugins');
    expect(res.ok(), `GET /plugins → ${res.status()}`).toBeTruthy();
    const body = await res.text();
    expect(body.toLowerCase()).toMatch(/kubewaf/);
  });

  test('overview + WAF + RuleSet + SecRules screenshots', async ({ page }) => {
    await gotoKubeWAF(page, '/kubewaf/overview');
    await shot(page, '01-overview.png');
    await expect(page.getByText(/kubeWAF|WAFs|Overview|Ready/i).first()).toBeVisible({
      timeout: 45_000,
    });

    await gotoKubeWAF(page, '/kubewaf/wafs');
    await expect(page.getByText(wafName).first()).toBeVisible({ timeout: 45_000 });
    await shot(page, '02-waf-list.png');

    await gotoKubeWAF(page, `/kubewaf/wafs/${wafNS}/${wafName}`);
    await expect(page.getByText(wafName).first()).toBeVisible({ timeout: 45_000 });
    await expect(page.getByText(/CRS Enabled/i).first()).toBeVisible();
    // Path B: engine CRS includes are off; structured RuleSet is attached.
    await expect(page.getByText('false').first()).toBeVisible();
    await expect(page.getByText(rulesetName).first()).toBeVisible();
    await shot(page, '03-waf-detail.png');

    // Live sections (health / requests / noisy rules / exclusions) sit below extraInfo.
    for (const label of [/Request|Deny|Noisy|Exclusion|Live traffic|Relationships/i]) {
      const el = page.getByText(label).first();
      if (await el.isVisible({ timeout: 3_000 }).catch(() => false)) {
        await el.scrollIntoViewIfNeeded();
      }
    }
    await shot(page, '04-waf-detail-live.png');

    await gotoKubeWAF(page, '/kubewaf/observe');
    await expect(page.getByText(/Observe|Flows|Allow|Deny|Service map/i).first()).toBeVisible({
      timeout: 45_000,
    });
    await shot(page, '08-observe.png');

    await gotoKubeWAF(page, '/kubewaf/observe?tab=logs');
    await expect(page.getByRole('tab', { name: /^Logs$/i })).toHaveAttribute('aria-selected', 'true', {
      timeout: 15_000,
    });
    await expect(page.getByText(/Eval log|Follow|no waf\.eval/i).first()).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, '09-observe-logs.png');

    await gotoKubeWAF(page, '/kubewaf/observe?tab=metrics');
    await expect(page.getByRole('tab', { name: /^Metrics$/i })).toHaveAttribute('aria-selected', 'true', {
      timeout: 15_000,
    });
    await expect(page.getByText(/Catalog|Per WAF|TX \(5m/i).first()).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, '10-observe-metrics.png');

    await gotoKubeWAF(page, `/kubewaf/rulesets/${wafNS}/${rulesetName}`);
    await expect(page.getByText(rulesetName).first()).toBeVisible({ timeout: 45_000 });
    await shot(page, '05-ruleset-detail.png');

    await gotoKubeWAF(page, '/kubewaf/secrules');
    await expect(page.getByText(/SecRule/i).first()).toBeVisible({ timeout: 45_000 });
    // Full CRS Path B is hundreds of SecRules; the list must not be empty.
    const rows = page.locator('table tbody tr');
    await expect(rows.first()).toBeVisible({ timeout: 45_000 });
    await shot(page, '06-secrules-list.png');

    // Open the first listed rule so the SecLang editor is in the shot.
    const firstLink = page.locator('table tbody tr a').first();
    if (await firstLink.isVisible().catch(() => false)) {
      await firstLink.click();
      await expect(page.getByText(/SecLang|SecRule|rule/i).first()).toBeVisible({
        timeout: 30_000,
      });
      await shot(page, '07-secrule-detail.png');
    }
  });
});
