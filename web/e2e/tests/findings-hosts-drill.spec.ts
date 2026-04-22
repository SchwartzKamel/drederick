import { test, expect } from "@playwright/test";
import { FindingsPage } from "../pages";

// NOTE: host list + detail drill-down is phase-3 UI work. Current scaffold
// renders a placeholder on /findings/hosts. Test stays fixme until the
// list/detail view lands (web/src/pages/Findings/*).
test.fixme("findings hosts: list → detail → tab switch", async ({ page }) => {
  const findings = new FindingsPage(page);
  await findings.gotoHosts();
  await expect(page.locator("body")).toContainText(/opponent-1|10\.0\.0\.10/);
  const firstRow = page.getByRole("link", { name: /opponent-1|10\.0\.0\.10/i }).first();
  await firstRow.click();
  await expect(page.locator("body")).toContainText(/services|cves|exploit/i);
});

test("findings hosts endpoint returns seeded host", async ({ page }) => {
  const resp = await page.request.get("/api/findings/hosts");
  expect(resp.ok()).toBe(true);
  const body = await resp.text();
  expect(body).toContain("opponent-1.ring.local");
  expect(body).toContain("10.0.0.10");
});
