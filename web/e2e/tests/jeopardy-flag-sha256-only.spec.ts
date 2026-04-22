import { test } from "@playwright/test";

test("jeopardy flag rendered as sha256 only", async ({ page }) => {
  test.fixme(
    true,
    "Requires a seeded Jeopardy session with a solved challenge row. " +
      "Jeopardy data lives in the process-lifetime CtfSessionManager — no " +
      "SQLite seed path exists, and the test-only seed endpoint is not " +
      "available. Revisit when a JeopardySessionManager.SeedForTests hook " +
      "lands (src/Drederick.Web/Jeopardy/). Meanwhile, the SessionDetail " +
      "component is expected to use <RedactedValue/> for flag_sha256.",
  );
});
