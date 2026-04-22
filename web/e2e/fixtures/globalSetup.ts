import { seedFindingsDb } from "./seedFindingsDb";
import * as fs from "node:fs";
import { OUT_DIR } from "./constants";

/**
 * Playwright globalSetup — runs once before the webServer boots.
 *
 * Seeds findings.db with canary rows so invariant tests can assert the
 * backend's projections never leak plaintext. The webServer is spawned
 * with --out pointing at the same OUT_DIR so findings.db is visible.
 */
export default async function globalSetup(): Promise<void> {
  fs.mkdirSync(OUT_DIR, { recursive: true });
  seedFindingsDb();
}
