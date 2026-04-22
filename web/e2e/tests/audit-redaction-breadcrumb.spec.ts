import { test, expect } from "@playwright/test";
import { AuditPage } from "../pages";
import { CANARY_AUDIT_PLAINTEXT } from "../fixtures/constants";

/**
 * The seed appended a canary audit entry containing
 * `flag{canary_audit_abc}` inside `data._canary`. When the audit page
 * renders it must not leak that plaintext. The phase-1 scaffold renders
 * raw JSONL rows, so today this test is a fixme with a breadcrumb —
 * convert to a hard assertion once the audit page ships a redaction
 * pipeline (web/src/pages/Audit/* should walk JSON values and elide
 * anything that isn't a known safe key).
 *
 * The backend invariant ("the harness itself never writes plaintext into
 * audit.jsonl") is covered by C# tests in tests/Drederick.Tests/; this
 * spec covers the DOM side only.
 */

test.fixme("audit page redacts canary plaintext from DOM", async ({ page }) => {
  const audit = new AuditPage(page);
  await audit.goto();
  await page.waitForLoadState("networkidle").catch(() => {});

  const rows = page.getByRole("button", { name: /expand|details|toggle/i });
  const n = await rows.count();
  for (let i = 0; i < Math.min(n, 5); i++) {
    await rows.nth(i).click().catch(() => {});
  }

  const dom = await page.content();
  expect(
    dom.includes(CANARY_AUDIT_PLAINTEXT),
    `Audit plaintext canary leaked in DOM: ${CANARY_AUDIT_PLAINTEXT}`,
  ).toBe(false);
});

test("audit page renders without crashing", async ({ page }) => {
  const audit = new AuditPage(page);
  const resp = await audit.goto();
  expect(resp?.status()).toBeLessThan(400);
});
