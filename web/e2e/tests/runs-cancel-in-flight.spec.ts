import { test } from "@playwright/test";

test("runs: cancel in-flight run transitions status", async ({ page }) => {
  test.fixme(
    true,
    "Cancel flow requires a successful start — blocked behind the same " +
      "Runs form surface breadcrumb as runs-start-happy-path.spec.ts. " +
      "The backend surface is POST /api/runs/{id}/cancel (see " +
      "src/Drederick.Web/Endpoints/RunsEndpoints.cs); enable once the " +
      "happy-path spec can produce a run id.",
  );
});
