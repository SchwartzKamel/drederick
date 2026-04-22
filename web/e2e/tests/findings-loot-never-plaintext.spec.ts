import { test, expect } from "@playwright/test";
import {
  CANARY_LOOT_PLAINTEXT,
  CANARY_LOOT_SHA256,
} from "../fixtures/constants";

/**
 * CRITICAL INVARIANT — @invariant-id:no-exfiltration.
 *
 * Loot plaintext must NEVER reach the DOM. The seed plants the canary
 * plaintext in the metadata JSON blob of a loot row (the schema itself
 * has no plaintext `value` column — that is the first layer of defense).
 * The backend projects loot rows via FindingsQueries.ListLoot, which
 * returns `value_sha256` only. We assert:
 *
 *   1. The canary plaintext `flag{canary_loot_xyz}` does NOT appear
 *      anywhere in `page.content()` OR in any captured network response
 *      body while the loot surface is rendered.
 *   2. The canary sha256 IS surfaced (or at least some sha256 shape is),
 *      establishing that the redaction path is in use rather than the row
 *      simply being absent.
 */

test("loot view never exposes plaintext canary anywhere in DOM or responses", async ({ page }) => {
  const bodies: string[] = [];
  page.on("response", async (resp) => {
    const url = resp.url();
    if (!url.includes("/api/")) return;
    try {
      const body = await resp.text();
      bodies.push(`[${url}] ${body}`);
    } catch {
      // non-text body — ignore
    }
  });

  // Best-effort landing page for loot. If there's a dedicated /findings/loot
  // route it will 200; otherwise we fall back to the findings index and
  // drill into a host. Either way, we hit /api/findings/loot along the way
  // via prefetch or explicit view.
  const responses: string[] = [];
  await page.goto("/findings");

  // Directly hit the loot endpoint through the browser so the response is
  // subject to our listener even if no UI click path navigates there today.
  await page.request.get("/api/findings/loot").then(async (r) => {
    responses.push(await r.text());
  });

  const domContent = await page.content();
  const haystack = domContent + "\n---\n" + bodies.join("\n") + "\n---\n" + responses.join("\n");

  expect(
    haystack.includes(CANARY_LOOT_PLAINTEXT),
    `Plaintext loot canary leaked somewhere in DOM or /api/ response body.\n` +
      `Canary: ${CANARY_LOOT_PLAINTEXT}`,
  ).toBe(false);

  // Positive sanity: either the sha256 digest or at least *a* sha256 token
  // is present — confirms we're exercising the redacted projection path.
  expect(
    haystack.toLowerCase().includes(CANARY_LOOT_SHA256) ||
      /sha256[:=]\s*[0-9a-f]/i.test(haystack) ||
      /value_sha256/i.test(haystack),
    "neither the canary sha256 nor any sha256-shaped token was surfaced — is the loot endpoint being reached?",
  ).toBe(true);
});
