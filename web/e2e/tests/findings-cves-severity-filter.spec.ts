import { test, expect } from "@playwright/test";
import { FindingsPage } from "../pages";

// NOTE: the CVEs severity-filter chip surface is phase-3 UI. For now we
// assert the backend filter parameter works; the visual chip flip lands
// fixme'd until web/src/pages/Findings/CvesList.tsx ships filter chips.
test.fixme("findings CVEs severity filter chips", async ({ page }) => {
  const findings = new FindingsPage(page);
  await findings.gotoCves();
  const criticalChip = page.getByRole("button", { name: /^critical$/i }).first();
  await criticalChip.click();
  await expect(page.locator("body")).toContainText(/CVE-2021-23017/);
});

test("findings CVEs endpoint filters by severity", async ({ page }) => {
  const all = await page.request.get("/api/findings/cves");
  expect(all.ok()).toBe(true);
  const allBody = await all.text();
  // Seeded: 2 critical (CVE-2021-23017, CVE-2017-7494), 1 medium.
  expect(allBody).toContain("CVE-2021-23017");

  const critical = await page.request.get("/api/findings/cves?severity=critical");
  expect(critical.ok()).toBe(true);
  const critBody = await critical.text();
  expect(critBody).toContain("CVE-2021-23017");
  // CVE-2020-14145 is medium (cvss 5.9) — must not appear in critical list.
  expect(critBody).not.toContain("CVE-2020-14145");
});
