import { test, expect } from "@playwright/test";
import { OUT_OF_SCOPE_TARGET, SCOPE_FILE } from "../fixtures/constants";

/**
 * A run submission whose target sits outside the allow-list must be
 * rejected. We hit the backend /api/runs endpoint directly so this test
 * exercises the scope check regardless of SPA form state.
 *
 * @invariant-id:scope-in-every-tool, :scope-default-deny
 */

test("runs: out-of-scope target is rejected by backend", async ({ page }) => {
  const resp = await page.request.post("/api/runs", {
    data: {
      targets: [OUT_OF_SCOPE_TARGET],
      scope_path: SCOPE_FILE,
    },
    failOnStatusCode: false,
  });

  // Expect a 4xx with a scope-related error. The exact shape varies by
  // RunsEndpoints; we tolerate either a RFC7807-style `detail` or a
  // `{error:"...scope..."}` envelope.
  expect(resp.status(), "scope violation must be a 4xx").toBeGreaterThanOrEqual(400);
  expect(resp.status(), "scope violation must not be 5xx").toBeLessThan(500);

  const body = await resp.text();
  expect(body).toMatch(/scope|out.?of.?scope|not.*sanction|refus/i);
});
