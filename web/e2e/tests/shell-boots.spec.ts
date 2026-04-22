import { test, expect } from "@playwright/test";
import { ShellPage } from "../pages";

test.describe("shell smoke", () => {
  test("loads and sidebar surfaces the 8 sections", async ({ page }) => {
    await page.goto("/");
    const shell = new ShellPage(page);

    // 8 sections (Runs, Findings, Jeopardy, Offensive, Audit, Scope, Doctor, Notes).
    const expected = ["Runs", "Findings", "Jeopardy", "Offensive", "Audit", "Scope", "Doctor", "Notes"];
    for (const label of expected) {
      await expect(shell.navLink(label), `sidebar missing ${label}`).toBeVisible();
    }

    // Health endpoint green.
    const health = await page.request.get("/api/health");
    expect(health.ok()).toBe(true);
    const healthBody = await health.json();
    expect(healthBody.status).toBe("ok");
  });

  // The Tatumism billing line ("I'm heavyweight champ, Drederick Tatum.") is
  // authored in web/src/lib/tatumisms.ts but isn't rendered on the current
  // phase-1 scaffold landing page. Revisit once the Footer/SplashHeader
  // surface ships (web/src/App.tsx).
  test.fixme("billing line rendered somewhere in shell", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByText(/I'm heavyweight champ/i)).toBeVisible();
  });
});
