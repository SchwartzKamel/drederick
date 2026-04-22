import { test, expect } from "@playwright/test";
import { DoctorPage } from "../pages";

/**
 * @invariant-id:doctor-workstation-only — the web Doctor surface is
 * read-only. No install / fix / apply buttons are permitted.
 *
 * Phase-1 scaffold may still be building this page. Absence of mutating
 * buttons is asserted strictly; the CLI-hint copy is a soft assertion
 * (fixme if the hint hasn't been authored yet).
 */

test("doctor page: no install/fix/apply buttons", async ({ page }) => {
  const doc = new DoctorPage(page);
  await doc.goto();

  const bad = page.getByRole("button", { name: /install|fix|apply|upgrade|remediate/i });
  expect(await bad.count(), "Doctor page exposes a mutating button").toBe(0);
});

test.fixme("doctor page: inline pointer to CLI", async ({ page }) => {
  const doc = new DoctorPage(page);
  await doc.goto();
  await expect(page.locator("body")).toContainText(/drederick doctor|CLI|terminal|command/i);
});
