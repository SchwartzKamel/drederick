import { test, expect } from "@playwright/test";
import * as fs from "node:fs";
import { FINDINGS_DB } from "../fixtures/constants";
import { seedFindingsDb } from "../fixtures/seedFindingsDb";

/**
 * When findings.db is absent the API must return a `no_database` shape
 * rather than 5xx. The phase-1 SPA doesn't yet render a dedicated
 * EmptyState for this — the data-side invariant is asserted via the API
 * directly; the DOM-side renders as a fixme until phase-3.
 *
 * Destructive: removes findings.db, tests, re-seeds.
 */

test("findings API returns no_database shape when DB missing", async ({ page }) => {
  if (fs.existsSync(FINDINGS_DB)) fs.unlinkSync(FINDINGS_DB);

  const resp = await page.request.get("/api/findings/summary");
  expect(resp.ok()).toBe(true);
  const body = await resp.json();
  expect(body.status ?? body.state).toBe("no_database");

  // Page must at least render (not crash).
  const pageResp = await page.goto("/findings");
  expect(pageResp?.status()).toBeLessThan(400);

  seedFindingsDb();
});

test.fixme("findings page renders no_database tatumism when DB missing", async ({ page }) => {
  if (fs.existsSync(FINDINGS_DB)) fs.unlinkSync(FINDINGS_DB);
  await page.goto("/findings");
  await expect(page.locator("body")).toContainText(/assembled|no.*database|has not yet/i);
  seedFindingsDb();
});
