import { test, expect } from "@playwright/test";
import { RunsPage } from "../pages";
import { IN_SCOPE_TARGET, SCOPE_FILE } from "../fixtures/constants";

test("runs: start a bout with in-scope target (happy path)", async ({ page }) => {
  const runs = new RunsPage(page);
  await runs.goto();

  const startBtn = runs.startBoutButton();
  const btnCount = await startBtn.count();
  test.fixme(btnCount === 0, "Start-a-bout button not found under current UI copy; POM selector needs tightening once the Runs form surface is finalized (web/src/pages/Runs/*).");

  // The rest of the happy-path flow depends on form shape (host field
  // label, scope_path field label, submit button label) which hasn't
  // been pinned. Leave as a fixme breadcrumb until the Runs form
  // component stabilises its testids.
  test.fixme(true, `Runs form DOM shape not pinned — fill + submit with target='${IN_SCOPE_TARGET}' and scope='${SCOPE_FILE}' once data-testid hooks land.`);
});
