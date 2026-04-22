import { test, expect } from "@playwright/test";
import { ScopePage } from "../pages";
import { SCOPE_FILE, IN_SCOPE_TARGET, OUT_OF_SCOPE_TARGET } from "../fixtures/constants";
import { scopeMtime } from "../fixtures/seedFindingsDb";

/**
 * @invariant-id:scope-file-read-only — record mtime before visiting /scope,
 * interact with the page (including running the validator twice), assert
 * mtime is unchanged.
 */

test("scope file mtime is unchanged after /scope visit + validator", async ({ page }) => {
  const before = scopeMtime(SCOPE_FILE);

  const scope = new ScopePage(page);
  await scope.goto();

  // Submit the validator directly via HTTP twice (POM-agnostic).
  for (let i = 0; i < 2; i++) {
    await page.request.post("/api/scope/validate", {
      data: { path: SCOPE_FILE, proposed_targets: [IN_SCOPE_TARGET, OUT_OF_SCOPE_TARGET] },
    });
  }

  // Also reload the page.
  await page.reload();

  const after = scopeMtime(SCOPE_FILE);
  expect(after, "scope file mtime changed — something wrote to it").toBe(before);
});
