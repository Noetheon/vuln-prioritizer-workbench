import { defineConfig, devices } from "@playwright/test"

const reuseExistingServer = process.env.VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER === "1"
const portPattern = /^\d+$/
const defaultBackendPort = "18000"
const defaultFrontendPort = "15173"
const backendPort = portPattern.test(
  process.env.VPW_PLAYWRIGHT_BACKEND_PORT ?? "",
)
  ? (process.env.VPW_PLAYWRIGHT_BACKEND_PORT ?? defaultBackendPort)
  : defaultBackendPort
const frontendPort = portPattern.test(
  process.env.VPW_PLAYWRIGHT_FRONTEND_PORT ?? "",
)
  ? (process.env.VPW_PLAYWRIGHT_FRONTEND_PORT ?? defaultFrontendPort)
  : defaultFrontendPort
const backendBaseUrl =
  process.env.VPW_E2E_BACKEND_URL ?? `http://127.0.0.1:${backendPort}`
const frontendBaseUrl =
  process.env.VPW_E2E_FRONTEND_URL ?? `http://127.0.0.1:${frontendPort}`
const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`

export default defineConfig({
  testDir: "./tests",
  testMatch: /.*\.spec\.ts/,
  timeout: 30_000,
  workers: 1,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: frontendBaseUrl,
    trace: "on-first-retry",
  },
  webServer: [
    {
      command: `cd .. && WORKBENCH_PLAYWRIGHT_BACKEND_PORT=${shellQuote(backendPort)} bash scripts/start-workbench-playwright-backend.sh`,
      reuseExistingServer,
      timeout: 120_000,
      url: `${backendBaseUrl}/api/v1/utils/health-check/`,
    },
    {
      command: `VITE_API_URL= VITE_DEV_PROXY_TARGET=${shellQuote(backendBaseUrl)} npm run dev -- --host 127.0.0.1 --port ${shellQuote(frontendPort)}`,
      reuseExistingServer,
      timeout: 120_000,
      url: `${frontendBaseUrl}/`,
    },
  ],
  projects: [
    {
      name: "chromium",
      testIgnore: /.*responsive-shell\.spec\.ts/,
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "mobile-chromium",
      testMatch: /.*responsive-shell\.spec\.ts/,
      use: { ...devices["Pixel 5"] },
    },
  ],
})
