import { test } from "@playwright/test";

test("audit: live tail toggle surfaces new events within 3s", async ({ page }) => {
  test.fixme(
    true,
    "Live-tail assertion depends on SignalR ScanEventBridge fanning a new " +
      "audit event to the browser. Triggering an audit event requires a " +
      "live run or a backend test-only endpoint; neither is wired for the " +
      "E2E harness. Revisit when /api/audit/test-emit or similar lands, or " +
      "once the webServer spawn supports injecting synthetic events.",
  );
});
