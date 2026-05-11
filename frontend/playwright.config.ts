import { defineConfig, devices } from "@playwright/test"

const reuseExistingServer = process.env.VPW_PLAYWRIGHT_REUSE_EXISTING_SERVER === "1"

export default defineConfig({
  testDir: "./tests",
  testMatch: /.*\.spec\.ts/,
  timeout: 30_000,
  workers: 1,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: "http://127.0.0.1:5173",
    trace: "on-first-retry",
  },
  webServer: [
    {
      command: "cd .. && bash scripts/start-workbench-playwright-backend.sh",
      reuseExistingServer,
      timeout: 120_000,
      url: "http://127.0.0.1:8000/api/v1/utils/health-check/",
    },
    {
      command: "npm run dev -- --host 127.0.0.1 --port 5173",
      reuseExistingServer,
      timeout: 120_000,
      url: "http://127.0.0.1:5173/login",
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
