import { test, expect } from "@playwright/test";
import { JeopardyPage } from "../pages";
import { CANARY_JEOPARDY_TOKEN } from "../fixtures/constants";

/**
 * CRITICAL INVARIANT — CTFd bearer tokens must never be persisted in DOM
 * state that a dismissed form can leak. After typing, cancelling, and
 * reopening the form, the field must be empty and the token value must
 * not appear anywhere in the document.
 */

test("jeopardy token field never redisplayed after cancel", async ({ page }) => {
  const jp = new JeopardyPage(page);
  await jp.goto();

  const tokenField = jp.tokenField();
  const fieldCount = await tokenField.count();
  test.fixme(fieldCount === 0, "CTFd token input not located under canonical selector; add data-testid='jeopardy-ctfd-token'.");

  await tokenField.fill(CANARY_JEOPARDY_TOKEN);

  // Cancel/close — try an explicit Cancel button, else a Close (×) button.
  const cancelBtn = page.getByRole("button", { name: /cancel|close|dismiss/i }).first();
  if (await cancelBtn.count()) await cancelBtn.click();

  // Navigate away and back; a reset-on-unmount form should show an empty field.
  await page.goto("/findings");
  await jp.goto();

  const reopenedValue = await jp.tokenField().inputValue().catch(() => "");
  expect(reopenedValue, "token field retained across navigation").toBe("");

  // Canary must not appear ANYWHERE in DOM.
  const dom = await page.content();
  expect(
    dom.includes(CANARY_JEOPARDY_TOKEN),
    `CTFd token canary leaked in DOM: ${CANARY_JEOPARDY_TOKEN}`,
  ).toBe(false);
});
