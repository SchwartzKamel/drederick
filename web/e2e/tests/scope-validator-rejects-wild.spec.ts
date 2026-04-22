import { test, expect } from "@playwright/test";
import { SCOPE_FILE, IN_SCOPE_TARGET, OUT_OF_SCOPE_TARGET } from "../fixtures/constants";

test("scope validator: accepts in-scope, rejects wild", async ({ page }) => {
  const resp = await page.request.post("/api/scope/validate", {
    data: {
      path: SCOPE_FILE,
      proposed_targets: [IN_SCOPE_TARGET, OUT_OF_SCOPE_TARGET],
    },
    failOnStatusCode: false,
  });

  expect(resp.ok(), `validate endpoint failed: ${resp.status()} body=${await resp.text()}`).toBe(true);
  const body = await resp.json();

  // Shape varies; we accept several equivalent envelopes.
  const serialised = JSON.stringify(body);
  expect(serialised).toContain(IN_SCOPE_TARGET);
  expect(serialised).toContain(OUT_OF_SCOPE_TARGET);

  // Accepted section includes the in-scope target.
  const accepted = body.accepted ?? body.in_scope ?? body.allowed ?? [];
  const rejected = body.rejected ?? body.out_of_scope ?? body.wild ?? body.refused ?? [];
  const acceptedStr = JSON.stringify(accepted);
  const rejectedStr = JSON.stringify(rejected);

  expect(acceptedStr, "in-scope target not marked accepted").toContain(IN_SCOPE_TARGET);
  expect(rejectedStr, "out-of-scope target not marked rejected").toContain(OUT_OF_SCOPE_TARGET);
});
