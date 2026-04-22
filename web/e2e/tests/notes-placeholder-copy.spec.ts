import { test, expect } from "@playwright/test";
import { NotesPage } from "../pages";

test("notes page: renders without crashing", async ({ page }) => {
  const notes = new NotesPage(page);
  const resp = await notes.goto();
  expect(resp?.status()).toBeLessThan(400);
});

test.fixme("notes page: placeholder copy with drederick note hint", async ({ page }) => {
  const notes = new NotesPage(page);
  await notes.goto();
  await expect(page.locator("body")).toContainText(/notebook|note|drederick note|operator/i);
});
