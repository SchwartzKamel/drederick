import { test } from "@playwright/test";

test("runs: unauthorized exec-poc category is gated", async ({ page }) => {
  test.fixme(
    true,
    "Runs form opt-in chips (exec-pocs / cred-attacks / payloads) are driven " +
      "by ServerCategoryGrants which is fixed at process start. The current " +
      "test-webServer spawn doesn't set the env flags, so all chips are " +
      "expected disabled; validating the visual 'disabled + tooltip' state " +
      "requires DOM hooks that have not been exposed yet. " +
      "Revisit when Runs form exposes data-testid='category-chip-exec-pocs'. " +
      "See src/Drederick.Web/Runs/ServerCategoryGrants.cs and " +
      "web/src/pages/Runs/RunStartForm.tsx.",
  );
});
