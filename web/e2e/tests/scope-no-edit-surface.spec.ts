import { test, expect } from "@playwright/test";
import { ScopePage } from "../pages";

/**
 * @invariant-id:scope-file-read-only
 *
 * The scope page must issue NO writes. The ONLY mutation it's allowed to
 * make is POST /api/scope/validate (which is server-side read-only). We
 * intercept network traffic and fail the test if any PUT/PATCH/DELETE
 * fires, or any POST to a path other than /api/scope/validate.
 */

test("scope page exposes no edit surface and issues no writes", async ({ page }) => {
  const forbiddenRequests: string[] = [];

  await page.route("**/*", (route) => {
    const req = route.request();
    const method = req.method();
    const url = req.url();
    const isWrite = method === "PUT" || method === "PATCH" || method === "DELETE";
    const isForbiddenPost =
      method === "POST" &&
      url.includes("/api/") &&
      !url.endsWith("/api/scope/validate") &&
      !url.includes("/api/scope/validate?");
    if (isWrite || isForbiddenPost) {
      forbiddenRequests.push(`${method} ${url}`);
    }
    route.continue();
  });

  const scope = new ScopePage(page);
  await scope.goto();

  // Poke the validator UI if available so we exercise any POST surface.
  const loadBtn = page.getByRole("button", { name: /load|view|show/i }).first();
  if (await loadBtn.count()) await loadBtn.click().catch(() => {});

  // Assert: no edit-y surface is present.
  const saveBtn = page.getByRole("button", { name: /^(save|edit|create|delete|add)/i });
  expect(await saveBtn.count(), `scope page exposes a mutating button`).toBe(0);

  const writeInputs = page.locator(
    "input[name*='save' i], input[name*='edit' i], textarea[name*='scope' i][readonly=false]",
  );
  // Note: an editable textarea paste-in-targets for the validator IS allowed
  // — that surface supplies proposed_targets, it doesn't mutate the file.
  // We only fail if a save/edit-labelled input exists.
  expect(await writeInputs.count()).toBe(0);

  // No forbidden writes observed.
  expect(forbiddenRequests, `scope page issued forbidden write requests: ${forbiddenRequests.join(", ")}`).toEqual([]);
});
