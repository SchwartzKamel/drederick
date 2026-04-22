import type { Page, Locator } from "@playwright/test";

/** Base class for page objects — common layout/shell locators. */
export class ShellPage {
  constructor(public readonly page: Page) {}
  sidebar(): Locator { return this.page.locator("nav").first(); }
  navLink(label: string): Locator { return this.sidebar().getByRole("link", { name: new RegExp(`^${label}$`, "i") }); }
  healthIndicator(): Locator { return this.page.getByTestId("health-indicator").or(this.page.locator("[data-health], [aria-label*='health' i]")).first(); }
  billingText(): Locator { return this.page.getByText(/I'm heavyweight champ/i); }
}

export class RunsPage extends ShellPage {
  goto() { return this.page.goto("/runs"); }
  startBoutButton(): Locator { return this.page.getByRole("button", { name: /start (a )?(bout|run)/i }); }
  runsTable(): Locator { return this.page.locator("table, [role=table]").first(); }
}

export class OffensivePage extends ShellPage {
  goto() { return this.page.goto("/offensive"); }
}

export class FindingsPage extends ShellPage {
  goto() { return this.page.goto("/findings"); }
  gotoHosts() { return this.page.goto("/findings/hosts"); }
  gotoCves() { return this.page.goto("/findings/cves"); }
  summaryCards(): Locator { return this.page.locator("[data-testid^='summary-'], [data-summary-card]").first(); }
}

export class JeopardyPage extends ShellPage {
  goto() { return this.page.goto("/jeopardy"); }
  tokenField(): Locator { return this.page.locator("input[name='ctfd_token'], input[id*='ctfd' i], input[type='password']").first(); }
}

export class ScopePage extends ShellPage {
  goto() { return this.page.goto("/scope"); }
  pathInput(): Locator { return this.page.locator("#scope-path"); }
  loadButton(): Locator { return this.page.getByRole("button", { name: /load|view|show/i }).first(); }
  validator(): Locator { return this.page.getByText(/validate|validator|proposed/i).first(); }
}

export class DoctorPage extends ShellPage {
  goto() { return this.page.goto("/doctor"); }
}

export class AuditPage extends ShellPage {
  goto() { return this.page.goto("/audit"); }
  liveToggle(): Locator { return this.page.getByRole("switch").or(this.page.getByRole("button", { name: /live|tail/i })).first(); }
}

export class NotesPage extends ShellPage {
  goto() { return this.page.goto("/notes"); }
}
