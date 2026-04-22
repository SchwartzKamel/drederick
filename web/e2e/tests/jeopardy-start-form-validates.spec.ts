import { test, expect } from "@playwright/test";
import { JeopardyPage } from "../pages";

test("jeopardy start form client-side validation", async ({ page }) => {
  const jp = new JeopardyPage(page);
  await jp.goto();

  // Try to submit without required fields — expect either HTML5 validity
  // guard or in-page error. The form may live behind a "Start session"
  // button; we're permissive about copy.
  const submit = page.getByRole("button", { name: /start|create|submit/i }).first();
  const submitCount = await submit.count();
  test.fixme(submitCount === 0, "Jeopardy start form submit button not yet pinned under canonical copy; add data-testid='jeopardy-session-submit' in pages/Jeopardy/*.");

  await submit.click();
  // No navigation should have occurred — if the form is valid it would
  // issue POST /api/jeopardy/sessions; assert we're still on the page.
  await expect(page).toHaveURL(/\/jeopardy(\?|$|\/$)/);
});
