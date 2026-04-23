import { test, expect } from "@playwright/test";
import { NotesPage } from "../pages";

test("notes page: renders without crashing", async ({ page }) => {
  const notes = new NotesPage(page);
  const resp = await notes.goto();
  expect(resp?.status()).toBeLessThan(400);
});

test("notes page: create form inputs render", async ({ page }) => {
  const notes = new NotesPage(page);
  await notes.goto();

  await expect(page.getByTestId("note-host")).toBeVisible();
  await expect(page.getByTestId("note-tag")).toBeVisible();
  await expect(page.getByTestId("note-body")).toBeVisible();
  await expect(page.getByTestId("note-submit")).toBeVisible();
});

test("notes page: create, surface, and delete a note round-trip", async ({ page }) => {
  const body = `e2e-note-${Date.now()}`;

  // Seed via the backend directly — extraHTTPHeaders carries the bearer.
  const created = await page.request.post("/api/notes", {
    data: { host: "10.9.9.9", tag: "e2e", body },
  });
  expect(created.status(), await created.text()).toBe(201);
  const noteId = (await created.json()).id as number;

  const notes = new NotesPage(page);
  await notes.goto();

  // Body is rendered verbatim.
  await expect(page.locator("body")).toContainText(body);
  await expect(page.locator("body")).toContainText("10.9.9.9");

  // Delete button removes the card.
  await page.getByTestId(`delete-note-${noteId}`).click();
  await expect(page.locator("body")).not.toContainText(body, { timeout: 5_000 });
});
