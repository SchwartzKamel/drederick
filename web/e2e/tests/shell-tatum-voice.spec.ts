import { test, expect } from "@playwright/test";

/**
 * Every page must render without crashing and should surface either
 * on-voice Tatumism copy OR the routed view's placeholder content. We
 * don't pin exact strings (tatumisms.ts evolves) — just assert the SPA
 * shell survives a direct navigation to each route.
 *
 * NOTE: in phase-1 scaffold state many routes render placeholder views
 * rather than finished Tatumism-rich empty states. The assertion is
 * deliberately tolerant; tighten once phase-3 pages land.
 */

const ROUTES = [
  "/runs",
  "/findings",
  "/jeopardy",
  "/offensive",
  "/audit",
  "/scope",
  "/doctor",
  "/notes",
];

for (const route of ROUTES) {
  test(`route renders without crash: ${route}`, async ({ page }) => {
    const resp = await page.goto(route);
    // SPA fallback should serve index.html for every route.
    expect(resp?.status(), `unexpected status for ${route}`).toBeLessThan(400);

    // Page title should be set (mounts the HTML head).
    await expect(page).toHaveTitle(/drederick/i);

    // Body should contain SOMETHING — not an empty shell.
    const text = await page.locator("body").textContent();
    expect(text?.trim().length ?? 0, `empty body on ${route}`).toBeGreaterThan(0);
  });
}

