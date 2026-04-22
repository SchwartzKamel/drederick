import * as path from "node:path";
import * as crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Shared constants and canary values for the E2E suite.
 *
 * Canaries are distinctive strings that should NEVER appear in the DOM or
 * API responses. Tests assert absence; if the SPA or backend regresses and
 * leaks, the canary string will trip the assertion loudly.
 */

export const OUT_DIR = path.resolve(__dirname, "../.tmp-out");
export const FINDINGS_DB = path.join(OUT_DIR, "findings.db");
export const AUDIT_LOG = path.join(OUT_DIR, "audit.jsonl");
export const SCOPE_FILE = path.resolve(__dirname, "test-scope.txt");

// ----- canaries -----
// Plaintext values that MUST NOT appear anywhere in the DOM or in any
// response body surfaced to the browser. Each is suffixed distinctively so
// any leak is unambiguous in test output.
export const CANARY_LOOT_PLAINTEXT = "flag{canary_loot_xyz}";
export const CANARY_AUDIT_PLAINTEXT = "flag{canary_audit_abc}";
export const CANARY_JEOPARDY_TOKEN = "ctfd_token_canary_9e13b57a";
export const CANARY_JEOPARDY_FLAG = "flag{canary_jeopardy_qrs}";

export function sha256(s: string): string {
  return crypto.createHash("sha256").update(s, "utf8").digest("hex");
}

export const CANARY_LOOT_SHA256 = sha256(CANARY_LOOT_PLAINTEXT);
export const CANARY_JEOPARDY_FLAG_SHA256 = sha256(CANARY_JEOPARDY_FLAG);

// In-scope and out-of-scope targets for scope-enforcement tests. The scope
// file (test-scope.txt) declares the `10.0.0.0/24` and `192.168.56.0/24`
// ranges; the "wild" values below are deliberately outside.
export const IN_SCOPE_TARGET = "10.0.0.10";
export const IN_SCOPE_TARGET_2 = "192.168.56.42";
export const OUT_OF_SCOPE_TARGET = "8.8.8.8";
