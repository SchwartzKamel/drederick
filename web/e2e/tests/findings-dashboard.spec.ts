import { test, expect } from "@playwright/test";
import { FindingsPage } from "../pages";

// NOTE: The phase-1 scaffold SPA renders placeholder content on /findings
// rather than live summary cards. This test stays as a fixme until
// FindingsSummaryCards is wired to /api/findings/summary.
test.fixme("findings dashboard: seeded summary counts and severity bar", async ({ page }) => {
  const findings = new FindingsPage(page);
  await findings.goto();
  await expect(page.locator("body")).toContainText(/\b2\b|\b3\b/);
  await expect(page.locator("body")).toContainText(/critical|medium|severity/i);
});

test("findings summary endpoint returns seeded counts", async ({ page }) => {
  const resp = await page.request.get("/api/findings/summary");
  expect(resp.ok(), `summary endpoint failed: ${resp.status()}`).toBe(true);
  const body = await resp.json();

  // Seeded: 2 hosts, 3 services, 2 findings, 1 exploit_run, 1 session, 1 loot.
  // Shape is a dict keyed by resource name — tolerate aliases.
  const serialized = JSON.stringify(body);
  expect(serialized).toMatch(/hosts?":\s*2/);
  expect(serialized).toMatch(/services?":\s*3/);
});
