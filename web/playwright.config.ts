import { defineConfig, devices } from "@playwright/test";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Playwright E2E configuration for the drederick SPA.
 *
 * Boots the ASP.NET backend (`src/Drederick.Web`) as a child process and
 * drives the SPA served from `wwwroot/` (i.e. the built Vite output).
 *
 * @invariant-id:scope-in-every-tool, :no-exfiltration, :audit-everything,
 * :scope-file-read-only — exercised via dedicated specs under ./e2e/tests.
 */

const PORT = Number(process.env.DRED_E2E_PORT ?? 17790);
const BASE_URL = `http://127.0.0.1:${PORT}`;

// Absolute paths — webServer `cwd` is the `web/` directory.
const REPO_ROOT = path.resolve(__dirname, "..");
const OUT_DIR = path.resolve(__dirname, "e2e/.tmp-out");
const TOKEN = "e2e-test-token-not-a-secret";

export default defineConfig({
  testDir: "./e2e/tests",
  fullyParallel: false, // shared backend + shared findings.db seed
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["github"], ["html", { open: "never" }]] : [["list"], ["html", { open: "never" }]],
  timeout: 30_000,
  expect: { timeout: 5_000 },

  use: {
    baseURL: BASE_URL,
    trace: "on-first-retry",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // Loopback-bound backend with bearer disabled (WebAppSettings.RequireBearer
    // is false on 127.0.0.1), so no auth header needed. The token is passed
    // anyway so any future tightening does not break the suite.
    extraHTTPHeaders: {
      Authorization: `Bearer ${TOKEN}`,
    },
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  globalSetup: "./e2e/fixtures/globalSetup.ts",

  webServer: {
    cwd: REPO_ROOT,
    // Build first, then invoke the produced DLL directly via `dotnet`
    // (as opposed to `dotnet run --project`, which switches the child's
    // cwd to the project directory — that breaks ScopeEndpoints'
    // "path must be within cwd" guard for scope files under `web/`).
    // By running the DLL directly we keep cwd = REPO_ROOT and the
    // absolute fixture paths we pass validate cleanly.
    command: [
      `export PATH="$HOME/.dotnet:$PATH"`,
      `dotnet build src/Drederick.Web/Drederick.Web.csproj --nologo -v quiet`,
      `DREDERICK_WEB_TOKEN=${TOKEN} ASPNETCORE_CONTENTROOT=${path.resolve(REPO_ROOT, "src/Drederick.Web")} ` +
        `dotnet src/Drederick.Web/bin/Debug/net10.0/drederick-web.dll` +
        ` --web-bind 127.0.0.1 --web-port ${PORT} --out ${OUT_DIR}`,
    ].join(" && "),
    url: `${BASE_URL}/api/health`,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    stdout: "pipe",
    stderr: "pipe",
  },
});
